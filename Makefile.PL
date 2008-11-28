# $Header: /Users/matisse/Desktop/CVS2GIT/matisse.net.cvs/Apache-AuthCookieDBI/Attic/Makefile.PL,v 1.7 2008/11/28 23:42:57 matisse Exp $
use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(

    # 'ORIGINAL_AUTHOR'       => 'Jacob Davies (jacob@well.com)',
    AUTHOR  => 'Matisse Enzer <matisse@cpan.org>',
    NAME    => 'Apache2::AuthCookieDBI',
    LICENSE => 'lgpl',

    #'VERSION_FROM' => 'AuthCookieDBI.pm', # finds $VERSION
    VERSION   => '2.04',
    PREREQ_PM => {
        'mod_perl2'           => '1.999022',
        'Apache2::AuthCookie' => '3.08',
        'Date::Calc'          => '0',
        'Digest::MD5'         => '0',
        'Apache::DBI'         => '0.91',
        'Apache2::Const'      => '0',
    },
);
