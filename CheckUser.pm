package Mail::CheckUser;

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);

require Exporter;

@ISA = qw(Exporter);

@EXPORT = qw();
@EXPORT_OK = qw(check_email
	        check_hostname
	        check_username);

$VERSION = '0.16';

use Carp;
use Net::DNS 0.12;
use Net::SMTP 2.13;
use IO::Handle 1.21;

use vars qw($Skip_Network_Checks $Skip_SMTP_Checks
            $Timeout $Treat_Timeout_As_Fail $Debug
            $Sender_Addr $Use_RCPT_Check);

# if it is true Mail::CheckUser doesn't make network checks
$Skip_Network_Checks = 0;
# if it is true Mail::CheckUser doesn't try to connect to mail
# server to check if user is valid
$Skip_SMTP_Checks = 0;
# timeout in seconds for network checks
$Timeout = 60;
# if it is true Mail::CheckUser treats timeouted checks as failed
# checks
$Treat_Timeout_As_Fail = 0;
# if it is true use MAIL/RCPT check instead of VRFY
$Use_RCPT_Check = 1;
# sender addr used in MAIL/RCPT check
$Sender_Addr = "check\@user.com";
# if true then enable debug mode
$Debug = 0;

# second half of ASCII table
my $_SECOND_ASCII = '';
for (my $i = 128; $i < 256; $i ++) {
    $_SECOND_ASCII .= chr($i);
}

# check_email EMAIL
sub check_email($);
# check_hostname_syntax HOSTNAME
sub check_hostname_syntax($);
# check_username_syntax USERNAME
sub check_username_syntax($);
# check_network HOSTNAME, USERNAME
sub check_network($$);
# check_user_on_host MSERVER, USERNAME, HOSTNAME, TIMEOUT
sub check_user_on_host($$$$);
# check_user_on_host_with_VRFY MSERVER, USERNAME, HOSTNAME, TIMEOUT
sub check_user_on_host_with_VRFY($$$$);
# check_user_on_host_with_RCPT MSERVER, USERNAME, HOSTNAME, TIMEOUT
sub check_user_on_host_with_RCPT($$$$);
# _calc_timeout FULL_TIMEOUT START_TIME
sub _calc_timeout($$);
# _pm_log LOG_STR
sub _pm_log($);

sub check_email($) {
    my($email) = @_;

    unless(defined $email) {
	carp __PACKAGE__ . "::check_email: \$email is undefined";
	return 0;
    }

    _pm_log '=' x 40;
    _pm_log "check_email: checking \"$email\"";

    # split email address on username and hostname
    my($username, $hostname) = split '@', $email;
    # return false if it impossible
    unless(defined $hostname) {
	_pm_log "check_email: can't split email \"$email\" on username and hostname";
	return 0;
    }

    my $ok = 1;
    $ok &= check_hostname_syntax $hostname;
    $ok &= check_username_syntax $username;
    if($Skip_Network_Checks) {
	_pm_log "check_email: skipping network checks";
    } else {
	$ok &= check_network $hostname, $username;
    }

    if($ok) {
	_pm_log "check_email: check is successful";
    } else {
	_pm_log "check_email: check is not successful";
    }

    return $ok;
}

sub check_hostname_syntax($) {
    my($hostname) = @_;

    _pm_log "check_hostname_syntax: checking \"$hostname\"";

    # check if hostname syntax is correct
    # NOTE: it doesn't strictly follow RFC821
    my $rAN = '[0-9a-zA-Z]';	# latin alphanum (don't use here \w: it can contain non-latin letters)
    my $rDM = "(?:$rAN+-)*$rAN+"; # domain regexp
    my $rHN = "(?:$rDM\\.)+$rDM"; # hostname regexp
    if($hostname !~ /^$rHN$/o) {
	_pm_log "check_hostname_syntax: syntax check failed for hostname \"$hostname\"";
	return 0;
    }

    _pm_log "check_hostname_syntax: exiting successfully";
    return 1;
}

sub check_username_syntax($) {
    my($username) = @_;

    _pm_log "check_username_syntax: checking \"$username\"";

    # check if username syntax is correct
    # NOTE: it doesn't strictly follow RFC821
    my $rST = '[^ <>\(\)\[\]\\\.,;:@"' . $_SECOND_ASCII . ']'; # allowed string regexp
    my $rUN = "(?:$rST+\\.)*$rST+"; # username regexp
    if($username !~ /^$rUN$/o) {
	_pm_log "check_username_syntax: syntax check failed for username \"$username\"";
	return 0;
    }

    _pm_log "check_username_syntax: exiting successfully";
    return 1;
}

sub check_network($$) {
    my($hostname, $username) = @_;

    _pm_log "check_network: checking \"$username\" on \"$hostname\"";

    # list of mail servers for hostname
    my @mservers = ();

    my $timeout = $Timeout;
    my $start_time = time;

    my $resolver = new Net::DNS::Resolver;

    my $tout = _calc_timeout($timeout, $start_time);
    if($tout == 0) {
	_pm_log "check_network: timeout";
	return $Treat_Timeout_As_Fail ? 0 : 1;
    }
    $resolver->tcp_timeout($tout);
    my @mx = mx($resolver, $hostname);
    # firstly check if timeout happen
    $tout = _calc_timeout($timeout, $start_time);
    if($tout == 0) {
	_pm_log "check_network: timeout";
	return $Treat_Timeout_As_Fail ? 0 : 1;
    }
    # secondly check result of query
    if(@mx) {
	# if MX record exists ...

	my %mservers = ();
	foreach my $rr (@mx) {
	    $mservers{$rr->exchange} = $rr->preference;
	}
	# here we get list of mail servers sorted by preference
	@mservers = sort { $mservers{$a} <=> $mservers{$b} } keys %mservers;
    } else {
	# if there is no MX record try hostname as mail server
	my $tout = _calc_timeout($timeout, $start_time);
	if($tout == 0) {
	    _pm_log "check_network: timeout";
	    return $Treat_Timeout_As_Fail ? 0 : 1;
	}
	$resolver->tcp_timeout($tout);
	my $res = $resolver->search($hostname);
	# firstly check if timeout happen
	$tout = _calc_timeout($timeout, $start_time);
	if($tout == 0) {
	    _pm_log "check_network: timeout";
	    return $Treat_Timeout_As_Fail ? 0 : 1;
	}
	# secondly check result of query
	if($res) {
	    @mservers = ($hostname);
	} else {
	    _pm_log "check_network: neither MX record nor host exist for \"$hostname\"";
	    return 0;
	}
    }

    if($Skip_SMTP_Checks) {
	_pm_log "check_network: skipping SMTP checks";
    } else {
	# check user on mail servers	
	foreach my $mserver (@mservers) {
	    my $tout = _calc_timeout($timeout, $start_time);
	    if($tout == 0) {
		_pm_log "check_network: timeout";
		return $Treat_Timeout_As_Fail ? 0 : 1;
	    }
	    my $res = check_user_on_host $mserver, $username, $hostname, $tout;

	    if($res == 1) {
		_pm_log "check_network: treat \"$username\" as valid user on \"$mserver\"";
		last;
	    } elsif($res == 0) {
		_pm_log "check_network: can't find \"$username\" on \"$mserver\"";
		return 0;
	    } else {
		next;
	    }
	}
    }

    _pm_log "check_network: exiting successfully";
    return 1;
}

sub check_user_on_host($$$$) {
    my($mserver, $username, $hostname, $timeout) = @_;

    if($Use_RCPT_Check) {
	return check_user_on_host_with_RCPT($mserver, $username, $hostname, $timeout);
    } else {
	return check_user_on_host_with_VRFY($mserver, $username, $hostname, $timeout);
    }
}

# returns -1 if it is not possible to get information about user existence
sub check_user_on_host_with_VRFY($$$$) {
    my($mserver, $username, $hostname, $timeout) = @_;

    _pm_log "check_user_on_host_with_VRFY: checking user \"$username\" on \"$mserver\"";

    my $start_time = time;

    # try to connect to mail server
    my $tout = _calc_timeout($timeout, $start_time);
    if($tout == 0) {
	_pm_log "check_user_on_host_with_VRFY: timeout";
	return $Treat_Timeout_As_Fail ? 0 : 1;
    }
    my $smtp = Net::SMTP->new($mserver, Timeout => $tout);
    unless(defined $smtp) {
	_pm_log "check_user_on_host_with_VRFY: unable to connect to \"$mserver\"";
	return -1;
    }

    # try to check if user is valid with VRFY command
    $tout = _calc_timeout($timeout, $start_time);
    if($tout == 0) {
	_pm_log "check_user_on_host_with_VRFY: timeout";
	return $Treat_Timeout_As_Fail ? 0 : 1;
    }
    $smtp->timeout($tout);
    if($smtp->verify("$username\@$hostname")) {
	return 1;
    } else {
	# check if verify returned error because of timeout
	my $tout = _calc_timeout($timeout, $start_time);
	if($tout == 0) {
	    _pm_log "check_user_on_host_with_VRFY: timeout";
	    return $Treat_Timeout_As_Fail ? 0 : 1;
	} else {
	    if($smtp->code == 550 or $smtp->code == 551 or $smtp->code == 553) {
		_pm_log "check_user_on_host_with_VRFY: no such user \"$username\" on \"$mserver\"";
		return 0;
	    } else {
		_pm_log "check_user_on_host_with_VRFY: unknown error in response";
		return 1;
	    }
	}
    }

    _pm_log "check_user_on_host_with_VRFY: exiting successfully";
    return 1;
}

# returns -1 if it is not possible to get information about user existence
sub check_user_on_host_with_RCPT($$$$) {
    my($mserver, $username, $hostname, $timeout) = @_;

    _pm_log "check_user_on_host_with_RCPT: checking user \"$username\" on \"$mserver\"";

    my $start_time = time;

    # try to connect to mail server
    my $tout = _calc_timeout($timeout, $start_time);
    if($tout == 0) {
	_pm_log "check_user_on_host_with_RCPT: timeout";
	return $Treat_Timeout_As_Fail ? 0 : 1;
    }
    my $smtp = Net::SMTP->new($mserver, Timeout => $tout);
    unless(defined $smtp) {
	_pm_log "check_user_on_host_with_RCPT: unable to connect to \"$mserver\"";
	return -1;
    }

    # try to check if user is valid with MAIL/RCPT commands
    $tout = _calc_timeout($timeout, $start_time);
    if($tout == 0) {
	_pm_log "check_user_on_host_with_RCPT: timeout";
	return $Treat_Timeout_As_Fail ? 0 : 1;
    }
    $smtp->timeout($tout);
    # first say MAIL
    unless($smtp->mail($Sender_Addr)) {
	# something wrong?

	# check for timeout
	if($tout == 0) {
	    _pm_log "check_user_on_host_with_RCPT: timeout";
	    return $Treat_Timeout_As_Fail ? 0 : 1;
	} else {
	    _pm_log "check_user_on_host_with_RCPT: can't say MAIL - " . $smtp->message;
	    return 1;
	}
    }
    if($smtp->to("$username\@$hostname")) {
	return 1;
    } else {
	# check if verify returned error because of timeout
	my $tout = _calc_timeout($timeout, $start_time);
	if($tout == 0) {
	    _pm_log "check_user_on_host_with_RCPT: timeout";
	    return $Treat_Timeout_As_Fail ? 0 : 1;
	} else {
	    if($smtp->code == 550 or $smtp->code == 551 or $smtp->code == 553) {
		_pm_log "check_user_on_host_with_RCPT: no such user \"$username\" on \"$mserver\"";
		return 0;
	    } else {
		_pm_log "check_user_on_host_with_RCPT: unknown error in response";
		return 1;
	    }
	}
    }

    _pm_log "check_user_on_host_with_RCPT: exiting successfully";
    return 1;
}

sub _calc_timeout($$) {
    my($full_timeout, $start_time) = @_;

    my $timeout = $full_timeout - (time - $start_time);

    if($timeout < 0) {
	return 0;
    } else {
	return $timeout;
    }
}

sub _pm_log($) {
    my($log_str) = @_;

    if($Debug) {
	print STDERR "$log_str\n";
    }
}

1;
__END__

=head1 NAME

Mail::CheckUser - checking email addresses for validness

=head1 SYNOPSIS

	use Mail::CheckUser qw(check_email);
	my $res = check_email($email_addr);

	use Mail::CheckUser;
	my $res = Mail::CheckUser::check_email($email_addr);

=head1 DESCRIPTION

This Perl module provides routines for checking validness of email address.

It makes several checks:

=over

=item 1

it checks syntax of email address;

=item 2

it checks if there any MX record for specified in email domain
or if there exist such host;

=item 3

it tries to connect to email server directly via SMTP to check if
mailbox is valid. Old versions of this module have performed this
check via VRFY command. Now module uses another check: it uses
combination of commands MAIL and RCPT which simulates fake sending of
email. Old VRFY check is still supported (see
I<$Mail::CheckUser::Use_RCPT_Check> global variable description in
L<"GLOBAL VARIABLES">). However please note VRFY can't detect bad
mailboxes in many cases while MAIL/RCPT works. For example hotmail.com
can be verified with MAIL/RCPT check while VRFY check doesn't work.

=back

If is possible to turn of all networking checks (second and third
checks). See L<"GLOBAL VARIABLES">.

This module was designed with CGIs (or any other dynamic Web content
programmed with Perl) in mind. Usually it is required to check fast
e-mail address in form. If check can't be finished in reasonable time
e-mail address should be treated as valid. This is default policy. By
default if timeout happens result of check is treated as positive (it
can be overridden - see L<"GLOBAL VARIABLES">).

=head1 EXAMPLE

This simple script checks if email address B<blabla@foo.bar> is
valid.

	use Mail::CheckUser qw(check_email);

	my $email = "blabla@foo.bar";

	if(check_email($email)) {
		print "E-mail address <$email> is OK\n";
	} else {
		print "E-mail address <$email> isn't valid\n";
	}

=head1 GLOBAL VARIABLES

Using global variables listed below it is possible to configure
I<check_email()>.

=over

=item *

I<$Mail::CheckUser::Skip_Network_Checks> - if it is true then do only
syntax checks. By default it is false.

=item *

I<$Mail::CheckUser::Skip_SMTP_Checks> - if it is true then do not try
to connect to mail server to check if user exist on it. By default it
is false.

=item *

I<$Mail::CheckUser::Use_RCPT_Check> - if it is true then use MAIL/RCPT
check instead VRFY check. By default it is true.

=item *

I<$Mail::CheckUser::Sender_Addr> - MAIL/RCPT check needs some mailbox
name to perform its check. Default value is "check\@user.com"

=item *

I<$Mail::CheckUser::Timeout> - timeout in seconds for network checks.
By default it is 60.

=item *

I<$Mail::CheckUser::Treat_Timeout_As_Fail> - if it is true
Mail::CheckUser treats timeouted checks as failed checks. By default
it is false.

=item *

I<$Mail::CheckUser::Debug> - if it is true then enable debug output on
STDERR. By default it is false.

=back

=head1 AUTHOR

Ilya Martynov B<m_ilya@agava.com>

=head1 SEE ALSO

perl(1).

=cut

