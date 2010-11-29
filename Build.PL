# $Id: Build.PL,v 1.5 2010/11/29 04:15:29 matisse Exp $
use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
    author      => 'Matisse Enzer <matisse@cpan.org>',
    module_name => 'Apache2::AuthCookieDBI',
    license     => 'lgpl',
    requires    => {
        'mod_perl2'           => 1.999022,
        'Apache2::AuthCookie' => 3.08,
        'DBI'                 => 1.40,
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

exit;
__END__

# 'ORIGINAL_AUTHOR'       => 'Jacob Davies (jacob@well.com)',
  