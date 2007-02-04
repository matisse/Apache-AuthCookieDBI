# $Header: /Users/matisse/Desktop/CVS2GIT/matisse.net.cvs/Apache-AuthCookieDBI/Attic/Makefile.PL,v 1.5 2007/02/04 19:45:10 matisse Exp $
use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
    # 'ORIGINAL_AUTHOR'       => 'Jacob Davies (jacob@well.com)',
    AUTHOR => 'Matisse Enzer <matisse@cpan.org>',
    NAME => 'Apache2::AuthCookieDBI',

    #'VERSION_FROM' => 'AuthCookieDBI.pm', # finds $VERSION
    PREREQ_PM => {
        'mod_perl2'           => '1.999022',
        'Apache2::AuthCookie' => '3.08',
        'Date::Calc'          => '0',
        'Digest::MD5'         => '0',
        'Apache::DBI'         => '0.91',
        'Apache2::Const'      => '0',
    }
);
