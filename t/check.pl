use vars qw($CUR_TEST);

use Mail::CheckUser qw(check_email);

$CUR_TEST = 0;

sub start($) {
	my($test_num) = @_;
	
	print "1..$test_num\n";
}

sub run_test($$) {
	my($email, $fail) = @_;
	
	$CUR_TEST ++;
	
	my $ok = check_email($email);
	$ok = ! $ok if $fail;
	
	if($ok) {
		print "ok $CUR_TEST\n";
	} else {
		print "not ok $CUR_TEST\n";
	}
}

sub run_timeout_test($$) {
	my($email, $timeout) = @_;
	
	$CUR_TEST ++;
	
	$Mail::CheckUser::Timeout = $timeout;
	
	my $start_time = time;
	check_email($email);
	
	if(time - $start_time < $timeout + 5) {
		print "ok $CUR_TEST\n";
	} else {
		print "not ok $CUR_TEST\n";
	}
}

1;
