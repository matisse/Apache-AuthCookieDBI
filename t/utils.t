use strict;
use warnings;
use FindBin qw($Bin);
use lib "$Bin/mock_libs";
use Crypt::CBC;

use Test::More tests => 7;
use_ok('Apache2::AuthCookieDBI');

test_defined_or_empty();
test_encrypt_session_key();

exit;

sub test_defined_or_empty {
    my $user = 'matisse';
    my $password;
    my @other_stuff = qw( a b c );
    is(
        Apache2::AuthCookieDBI::_defined_or_empty(
            $user, $password, @other_stuff
        ),
        5,
        '_defined_or_empty returns expected number of items.'
    );
}

sub test_encrypt_session_key {
    my $session_key = 'mock_session_key';
    my $secret_key  = 'mock secret key';
    my $auth_name   = 'test_encrypt_session_key';
    my $expected    = {
        none        => $session_key,
        des         => "DES:$secret_key:$session_key",
        idea        => "IDEA:$secret_key:$session_key",
        blowfish    => "Blowfish:$secret_key:$session_key",
        blowfish_pp => "Blowfish_PP:$secret_key:$session_key",
    };
    foreach my $encryption_type ( sort keys %{$expected} ) {
        my @args = ( $session_key, $secret_key, $auth_name, $encryption_type );
        my $mock_crypt_text =
          Apache2::AuthCookieDBI::_encrypt_session_key(@args);

        is(
            $mock_crypt_text,
            $expected->{$encryption_type},
            '_encrypt_session_key ' . join( q{,}, @args )
        );
    }
}
