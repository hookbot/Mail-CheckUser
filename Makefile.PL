use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'	   => 'Mail::CheckUser',
    'VERSION_FROM' => 'CheckUser.pm', # finds $VERSION
    'PREREQ_PM'    => { 'Net::SMTP'  => 2.13,
                        'Net::DNS'   => 0.12,
			'IO::Handle' => 1.21,
                      },
);
