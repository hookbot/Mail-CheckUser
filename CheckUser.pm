# Copyright (c) 1999,2000,2001,2002 by Ilya Martynov. All rights
# reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself.

package Mail::CheckUser;

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);

require Exporter;

@ISA = qw(Exporter);

@EXPORT = qw();
@EXPORT_OK = qw(check_email
                last_check
	        check_hostname
	        check_username);
$EXPORT_TAGS{constants} = [qw(CU_OK
                              CU_BAD_SYNTAX
                              CU_UNKNOWN_DOMAIN
                              CU_DNS_TIMEOUT
                              CU_UNKNOWN_USER
                              CU_SMTP_TIMEOUT
                              CU_SMTP_UNREACHABLE)];
push @EXPORT_OK, @{$EXPORT_TAGS{constants}};

$VERSION = '1.13';

use Carp;
BEGIN {
    # workaround against annoying warning under Perl 5.6+
    local $^W = $^W;
    if($] > 5.00503) {
	$^W = 0;
    }
    require Net::DNS;
    import Net::DNS;
}
use Net::SMTP;
use IO::Handle;

use vars qw($Skip_Network_Checks $Skip_SMTP_Checks
            $Timeout $Treat_Timeout_As_Fail $Debug
            $Sender_Addr $Helo_Domain $Last_Check);

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
# sender addr used in MAIL/RCPT check
$Sender_Addr = 'check@user.com';
# sender domain used in HELO SMTP command - if undef lets
# Net::SMTP use its default value
$Helo_Domain = undef;
# if true then enable debug mode
$Debug = 0;

# second half of ASCII table
my $_SECOND_ASCII = '';
for (my $i = 128; $i < 256; $i ++) {
    $_SECOND_ASCII .= chr($i);
}

# check_email EMAIL
sub check_email($);
# last_check
sub last_check();
# check_hostname_syntax HOSTNAME
sub check_hostname_syntax($);
# check_username_syntax USERNAME
sub check_username_syntax($);
# check_network HOSTNAME, USERNAME
sub check_network($$);
# check_user_on_host MSERVER, USERNAME, HOSTNAME, TIMEOUT
sub check_user_on_host($$$$);
# _calc_timeout FULL_TIMEOUT START_TIME
sub _calc_timeout($$);
# _pm_log LOG_STR
sub _pm_log($);
# _result RESULT, REASON
sub _result($$);

# check result codes
use constant CU_OK               => 0;
use constant CU_BAD_SYNTAX       => 1;
use constant CU_UNKNOWN_DOMAIN   => 2;
use constant CU_DNS_TIMEOUT      => 3;
use constant CU_UNKNOWN_USER     => 4;
use constant CU_SMTP_TIMEOUT     => 5;
use constant CU_SMTP_UNREACHABLE => 6;

sub check_email($) {
    my($email) = @_;

    unless(defined $email) {
	croak __PACKAGE__ . "::check_email: \$email is undefined";
    }

    _pm_log '=' x 40;
    _pm_log "check_email: checking \"$email\"";

    # split email address on username and hostname
    my($username, $hostname) = $email =~ /^(.*)@(.*)$/;
    # return false if it impossible
    unless(defined $hostname) {
	return _result(CU_BAD_SYNTAX, 'bad address format: missing @');
    }

    my $ok = 1;
    $ok &&= check_hostname_syntax $hostname;
    $ok &&= check_username_syntax $username if $ok;
    if($Skip_Network_Checks) {
	_pm_log "check_email: skipping network checks";
    } elsif ($ok) {
	$ok &&= check_network $hostname, $username;
    }

    return $ok;
}

sub last_check() {
    return $Mail::CheckUser::Last_Check;
}

sub check_hostname_syntax($) {
    my($hostname) = @_;

    _pm_log "check_hostname_syntax: checking \"$hostname\"";

    # check if hostname syntax is correct
    # NOTE: it doesn't strictly follow RFC822
    my $rAN = '[0-9a-zA-Z]';	# latin alphanum (don't use here \w: it can contain non-latin letters)
    my $rDM = "(?:$rAN+-)*$rAN+"; # domain regexp
    my $rHN = "(?:$rDM\\.)+$rDM"; # hostname regexp
    if($hostname =~ /^$rHN$/o) {
	return _result(CU_OK, 'correct hostname syntax')
    } else {
	return _result(CU_BAD_SYNTAX, 'bad hostname syntax');
    }
}

sub check_username_syntax($) {
    my($username) = @_;

    _pm_log "check_username_syntax: checking \"$username\"";

    # check if username syntax is correct
    # NOTE: it doesn't strictly follow RFC821
    my $rST = '[^ <>\(\)\[\]\\\.,;:@"' . $_SECOND_ASCII . ']'; # allowed string regexp
    my $rUN = "(?:$rST+\\.)*$rST+"; # username regexp
    if($username =~ /^$rUN$/o) {
	return _result(CU_OK, 'correct username syntax')
    } else {
	return _result(CU_BAD_SYNTAX, 'bad username syntax');
    }
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
    return _result(CU_DNS_TIMEOUT, 'DNS timeout') if $tout == 0;
    $resolver->tcp_timeout($tout);

    my @mx = mx($resolver, "$hostname.");
    $tout = _calc_timeout($timeout, $start_time);
    return _result(CU_DNS_TIMEOUT, 'DNS timeout') if $tout == 0;

    # check result of query
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
	return _result(CU_DNS_TIMEOUT, 'DNS timeout') if $tout == 0;
	$resolver->tcp_timeout($tout);

	my $res = $resolver->search("$hostname.", 'A');
	# check if timeout has happen
	$tout = _calc_timeout($timeout, $start_time);
	return _result(CU_DNS_TIMEOUT, 'DNS timeout') if $tout == 0;

	# check result of query
	if($res) {
	    @mservers = ($hostname);
	} else {
	    return _result(CU_UNKNOWN_DOMAIN, 'DNS failure: ' . $resolver->errorstring)
	}
    }

    if($Skip_SMTP_Checks) {
	return _result(CU_OK, 'skipping SMTP checks');
    } else {
	# check user on mail servers
	foreach my $mserver (@mservers) {
	    my $tout = _calc_timeout($timeout, $start_time);
	    return _result(CU_SMTP_TIMEOUT, 'SMTP timeout') if $tout == 0;

	    my $res = check_user_on_host $mserver, $username, $hostname, $tout;

	    return 1 if $res == 1;
	    return 0 if $res == 0;
	}

	return _result(CU_SMTP_UNREACHABLE,
		       'Cannot connect SMTP servers: ' .
		      join(', ', @mservers));
    }

    # it should be impossible to reach this statement
    die "Internal error";
}

sub check_user_on_host($$$$) {
    my($mserver, $username, $hostname, $timeout) = @_;

    _pm_log "check_user_on_host: checking user \"$username\" on \"$mserver\"";

    my $start_time = time;

    # disable warnings because Net::SMTP can generate some on timeout
    # conditions
    local $^W = 0;

    # try to connect to mail server
    my $tout = _calc_timeout($timeout, $start_time);
    return _result(CU_SMTP_TIMEOUT, 'SMTP timeout') if $tout == 0;

    my @hello_params = defined $Helo_Domain ? (Hello => $Helo_Domain) : ();
    my $smtp = Net::SMTP->new($mserver, Timeout => $tout, @hello_params);
    unless(defined $smtp) {
	_pm_log "check_user_on_host: unable to connect to \"$mserver\"";
	return -1;
    }

    # try to check if user is valid with MAIL/RCPT commands
    $tout = _calc_timeout($timeout, $start_time);
    return _result(CU_SMTP_TIMEOUT, 'SMTP timeout') if $tout == 0;
    $smtp->timeout($tout);

    # send MAIL FROM command
    unless($smtp->mail($Sender_Addr)) {
	# something wrong?

	# check for timeout
	return _result(CU_SMTP_TIMEOUT, 'SMTP timeout') if $tout == 0;

	_pm_log "check_user_on_host: can't say MAIL - " . $smtp->message;
	return -1;
    }

    # send RCPT TO command
    if($smtp->to("$username\@$hostname")) {
	return _result(CU_OK, 'SMTP server accepts username');
    } else {
	# check if verify returned error because of timeout
	my $tout = _calc_timeout($timeout, $start_time);
	return _result(CU_SMTP_TIMEOUT, 'SMTP timeout') if $tout == 0;

	if($smtp->code == 550 or $smtp->code == 551 or $smtp->code == 553) {
	    return _result(CU_UNKNOWN_USER, 'no such user');
	} else {
	    return _result(CU_OK, 'unknown error in response');
	    _pm_log "check_user_on_host: unknown error in response";
	    return 1;
	}
    }


    # it should be impossible to reach this statement
    die "Internal error";
}

sub _calc_timeout($$) {
    my($full_timeout, $start_time) = @_;

    my $now_time = time;
    my $passed_time = $now_time - $start_time;
    _pm_log "_calc_timeout: start - $start_time, now - $now_time";
    _pm_log "_calc_timeout: timeout - $full_timeout, passed - $passed_time";

    my $timeout = $full_timeout - $passed_time;

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

sub _result($$) {
    my($code, $reason) = @_;

    my $ok = 0;

    $ok = 1 if $code == CU_OK;
    $ok = 1 if $code == CU_SMTP_UNREACHABLE;
    $ok = 1 if $code == CU_DNS_TIMEOUT and not $Treat_Timeout_As_Fail;
    $ok = 1 if $code == CU_SMTP_TIMEOUT and not $Treat_Timeout_As_Fail;

    $Last_Check = { ok     => $ok,
		    code   => $code,
		    reason => $reason };

    my($sub) = (caller(1))[3] =~ /^.*::(.*)$/;

    _pm_log "$sub: check result is " .
            ($ok ? 'ok' : 'not ok') .
            ": [$code] $reason";

    return $ok;
}

1;
__END__

=head1 NAME

Mail::CheckUser - check email addresses for validity

=head1 SYNOPSIS

    use Mail::CheckUser qw(check_email);
    my $ok = check_email($email_addr);

    use Mail::CheckUser qw(:constants check_email last_check)
    my $ok = check_email($email_addr);
    print "DNS timeout\n"
        if last_check()->{code} == CU_DNS_TIMEOUT;

    use Mail::CheckUser;
    my $res = Mail::CheckUser::check_email($email_addr);


=head1 DESCRIPTION

This Perl module provides routines for checking validity of email address.

It makes several checks:

=over 4

=item 1

It checks the syntax of an email address.

=item 2

It checks if there any MX records or A records for the domain part
of the email address.

=item 3

It tries to connect to an email server directly via SMTP to check if
mailbox is valid.  Old versions of this module performed this check
via the VRFY command.  Now the module uses another check; it uses a
combination of MAIL and RCPT commands which simulates sending an
email.  It can detect bad mailboxes in many cases.  For example,
hotmail.com mailboxes can be verified with the MAIL/RCPT check.

=back

If is possible to turn off some or all networking checks (items 2 and 3).
See L<"GLOBAL VARIABLES">.

This module was designed with CGIs (or any other dynamic Web content
programmed with Perl) in mind.  Usually it is required to quickly
check e-mail addresses in forms.  If the check can't be finished in
reasonable time, the e-mail address should be treated as valid.  This
is the default policy.  By default if a timeout happens the result of
the check is treated as positive.  This behavior can be overridden -
see L<"GLOBAL VARIABLES">.

=head1 IMPORTANT WARNING

In many cases there is no way to detect the validity of email
addresses with network checks.  For example, non-monolithic mail
servers (such as Postfix and qmail) often report that a user exists
even if it is not so.  This is because in cases where the work of the
server is split among many components, the SMTP server may not know
how to check for the existence of a particular user.  Systems like
these will reject mail to unknown users, but they do so after the SMTP
conversation.  In cases like these, the only absolutely sure way to
determine whether or not a user exists is to actually send a mail and
wait to see if a bounce messages comes back.  Obviously, this is not a
workable strategy for this module.  Does it mean that the network
checks in this module are useless?  No.  For one thing, just the DNS
checks go a long way towards weeding out mistyped domain parts.  Also,
there are still many SMTP servers that will reject a bad address
during the SMTP conversation.  Because of this, it's still a useful
part of checking for a valid email address.  And this module was
designed such that if there is exists possibility (however small) that
the email address is valid, it will be treated as valid by this
module.

Another warning is about C<$Mail::CheckUser::Treat_Timeout_As_Fail>
global variable.  Use it carefully - if it is set to true then some
valid email addresses can be treated as bad simply because an SMTP or
DNS server responds slowly.

=head1 EXAMPLE

This simple script checks if email address C<blabla@foo.bar> is
valid.

    use Mail::CheckUser qw(check_email last_check);

    my $email = 'blabla@foo.bar';

    if(check_email($email)) {
        print "E-mail address <$email> is OK\n";
    } else {
	print "E-mail address <$email> isn't valid: ",
              last_check()->{reason}, "\n";
    }

=head1 SUBROUTINES

=over 4

=item $ok = check_email($email)

Validates email address C<$email>.  Return true if email address is
valid and false otherwise.

=item $res = last_check()

Returns detailed result of last check made with C<check_email> as hash
reference:

    { ok => OK, code => CODE, reason => REASON }

=over 4

=item OK

True if last checked email address is valid.  False otherwise.

=item CODE

A number which describes result of last check.  See L<"CONSTANTS">.

=item REASON

A string which describes result of last check.

=back

=back

=head1 CONSTANTS

Constants used by C<last_check> to describe result of last check can
be exported with

    use Mail::CheckUser qw(:constants)

List of all defined constants:

=over 4

=item CU_OK

Check is successful.

=item CU_BAD_SYNTAX

Bad syntax of email address.

=item CU_UNKNOWN_DOMAIN

Mail domain mentioned in email address is unknown.

=item CU_DNS_TIMEOUT

Timeout has happen during DNS checks.

=item CU_UNKNOWN_USER

User is unknown on SMTP server.

=item CU_SMTP_TIMEOUT

Timeout has happen during SMTP checks.

=item CU_SMTP_UNREACHABLE

All SMTP servers for mail domain were found unreachable during SMTP
checks.

=back

=head1 GLOBAL VARIABLES

It is possible to configure C<check_email> using the global variables listed
below.

=over 4

=item $Mail::CheckUser::Skip_Network_Checks

If true then do only syntax checks.  By default it is false.

=item $Mail::CheckUser::Skip_SMTP_Checks

If it is true then do not try to connect to mail server to check if a
user exists.  If this is true, and
C<$Mail::CheckUser::Skip_Network_Checks> is false, only syntax and DNS
checks are performed.  By default it is false.

=item $Mail::CheckUser::Sender_Addr

MAIL/RCPT check needs an email address to use as the 'From' address
when performing its checks.  The default value is C<check@user.com>.

=item $Mail::CheckUser::Helo_Domain

Sender domain used in HELO SMTP command.  If undef
L<Net::SMTP|Net::SMTP> is allowed to use its default value.  By
default it is undef.

=item Mail::CheckUser::Timeout

Timeout in seconds for network checks.  By default it is C<60>.

=item $Mail::CheckUser::Treat_Timeout_As_Fail

If it is true C<Mail::CheckUser> treats checks that time out as
failed.  By default it is false.

=item $Mail::CheckUser::Debug

If it is true then enable debug output on C<STDERR>.  By default it is
false.

=back

=head1 AUTHOR

Ilya Martynov B<ilya@martynov.org>

=head1 COPYRIGHT

Copyright (c) 1999,2000,2001,2002 by Ilya Martynov.  All rights
reserved.

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

perl(1).

=cut

