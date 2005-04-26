# $Id: Makefile.PL,v 1.4 2005/04/26 15:45:15 matisse Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    'AUTHOR'       => 'Jacob Davies (jacob@well.com)',
    'NAME'	   => 'Apache2::AuthCookieDBI',
    'VERSION_FROM' => 'AuthCookieDBI.pm', # finds $VERSION
    'PREREQ_PM'    => {
        'mod_perl2'          => '1.999022',
        'Apache2::AuthCookie' => '3.08',
        'Date::Calc'          => '0',
        'Digest::MD5'         => '0',
        'Apache::DBI'         => '0.91',
        'Apache2::Const'      => '0',
    }
);
