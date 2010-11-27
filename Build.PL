# $Id: Build.PL,v 1.2 2010/11/27 19:27:41 matisse Exp $
use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
    module_name => 'Apache2::AuthCookieDBI',
    license     => 'lgpl',
    requires    => {
        'mod_perl2'           => 1.999022,
        'Apache2::AuthCookie' => 3.08,
        'Apache::DBI'         => 0.91,
        'Apache2::Const'      => 0,
        'Apache2::RequestRec' => 0,
        'Apache2::ServerUtil' => 0,
        'Carp'                => 0,
        'Crypt::CBC'          => 2.13,
        'Date::Calc'          => 0,
        'Digest::MD5'         => 0,
        'FindBin'             => 0,
    },
    build_requires => { 'Test::More' => 0.4, },
    create_makefile_pl => 'traditional',
);

$build->create_build_script();

=pod
    # 'ORIGINAL_AUTHOR'       => 'Jacob Davies (jacob@well.com)',
    AUTHOR  => 'Matisse Enzer <matisse@cpan.org>',
    NAME    => 'Apache2::AuthCookieDBI',
    LICENSE => 'lgpl',

    'VERSION_FROM' => 'Apache2::AuthCookieDBI.pm', # finds $VERSION
    PREREQ_PM => {
        'mod_perl2'           => '1.999022',
        'Apache2::AuthCookie' => '3.08',
        'Date::Calc'          => '0',
        'Digest::MD5'         => '0',
        'Apache::DBI'         => '0.91',
        'Apache2::Const'      => '0',
    },
