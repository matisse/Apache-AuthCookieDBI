# $Id: Makefile.PL,v 1.3 2003/10/10 20:53:15 jacob Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    'AUTHOR'       => 'Jacob Davies (jacob@well.com)',
    'NAME'	   => 'Apache::AuthCookieDBI',
    'VERSION_FROM' => 'AuthCookieDBI.pm', # finds $VERSION
    'PREREQ_PM'    => {
        'Apache::AuthCookie' => '0',
        'Date::Calc'         => '0',
        'Digest::MD5'        => '0',
        'Apache::DBI'        => '0',
        'Apache::Constants'  => '0',
        'Apache'             => '0',
    }
);
