use Mail::CheckUser qw(check_email);
 
require 't/check.pl';
 
# syntax test
$Mail::CheckUser::Skip_Network_Checks = 1;
 
@ok_emails = qw(foo@aaa.bbb foo.bar@aaa.bbb foo@aaa.bbb.ccc foo.bar@aaa.bbb.ccc foo@aaa.aaa);
@bad_emails = qw(bar@aaa .bar@aaa.bbb bar.@aaa.bbb bar@aaa.bbb. bar@.aaa.bbb <>[]@aaa.bbb);
push @bad_emails, 'qqqqqqqqq wwwwwwww@test.com';
push @bad_emails, 'Ваш e-mail OlegNick@nursat.kz';
push @bad_emails, 'РусскийТекст@nursat.kz';
 
start(scalar(@ok_emails) + scalar(@bad_emails));
 
foreach my $email (@ok_emails) {
        run_test($email, 0);
}
 
foreach my $email (@bad_emails) {
        run_test($email, 1);
}
