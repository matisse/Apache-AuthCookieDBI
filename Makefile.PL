use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'AUTHOR'       => 'Jacob Davies (jacob@well.com)',
    'NAME'	   => 'Apache::AuthCookieDBI',
    'VERSION_FROM' => 'AuthCookieDBI.pm', # finds $VERSION
    'PREREQ_PM'   => {
        'Apache::AuthCookie'    => '0',
        }
);
