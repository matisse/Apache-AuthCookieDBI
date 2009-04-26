use strict;
use warnings;
use English qw(-no_match_vars);
use FindBin qw($Bin);
use lib "$Bin/mock_libs";
use Crypt::CBC;                   # from mocks
use Digest::MD5 qw( md5_hex );    # from mocks
use Data::Dumper;

use Test::More tests => 30;

my $PACKAGE      = 'Apache2::AuthCookieDBI';
my $EMPTY_STRING = q{};

use_ok($PACKAGE);
test_defined_or_empty();
test_encrypt_session_key();
test_dir_config_var();
test_authen_ses_key();
test_get_cipher_type();
test__dbi_connect();

exit;

sub set_up {
    my $auth_name   = shift;
    my $mock_config = shift;
    my $r           = Apache2::RequestRec->new(
        auth_name   => $auth_name,
        mock_config => $mock_config
    );    # from mock_libs
    return $r;
}

sub test_authen_ses_key {
    my $auth_name   = 'testing_authen_ses_key';
    my $secret_key  = 'test secret key';
    my $mock_config = {
        $auth_name . 'DBI_DSN'             => 'test DSN',
        $auth_name . 'DBI_SecretKey'       => $secret_key,
        $auth_name . 'DBI_User'            => $auth_name,
        $auth_name . 'DBI_Password'        => 'test DBI password',
        $auth_name . 'DBI_UsersTable'      => 'users',
        $auth_name . 'DBI_UserField'       => 'user',
        $auth_name . 'DBI_passwordfield'   => 'password',
        $auth_name . 'DBI_crypttype'       => 'none',
        $auth_name . 'DBI_groupstable'     => 'groups',
        $auth_name . 'DBI_groupfield'      => 'grp',
        $auth_name . 'DBI_groupuserfield'  => 'user',
        $auth_name . 'DBI_encryptiontype'  => 'none',
        $auth_name . 'DBI_sessionlifetime' => '00-24-00-00',
        $auth_name . 'DBI_sessionmodule'   => 'none',
    };
    my $r                  = set_up( $auth_name, $mock_config );
    my $expected_user      = 'expected_username';
    my $issue_time         = '2006-02-04-10-34-23';
    my $expire_time        = '9999-02-04-10-45-00';
    my $session_id         = 'test_session_id';
    my $extra_session_info = 'extra:info';
    my $hashed_string = 'bad-key-stored-in-ticket';   # not a 32 char hex string
    my $encrypted_session_key = join( q{:},
        $expected_user, $issue_time, $expire_time,
        $session_id,    $hashed_string );

    Apache2::AuthCookieDBI->authen_ses_key( $r, $encrypted_session_key );
    like(
        $r->log_error->[-1],
        qr/ bad \s encrypted \s session_key /xm,
        'authen_ses_key() on bad encrypted key'
    );

    $r = set_up( $auth_name, $mock_config );

    my $seperator   = q{:};
    my $public_part = join( $seperator,
        $expected_user, $issue_time, $expire_time,
        $session_id,    $extra_session_info );

    my $plaintext_key = join( $seperator, $public_part, $secret_key );

    my $md5_hash = md5_hex($plaintext_key);

    $hashed_string = md5_hex( join( $seperator, $secret_key, $md5_hash ) );

    $encrypted_session_key = join( q{:}, $public_part, $hashed_string );

    my $got_user
        = Apache2::AuthCookieDBI->authen_ses_key( $r, $encrypted_session_key );
    is( $got_user, $expected_user, 'authen_ses_key() on plaintext key' )
        || diag join( "\n", @{ $r->log_error() } );
    return 1;
}

sub test_dir_config_var {
    my $auth_name       = 'testing_dir_config_var';
    my $variable_wanted = 'Arbitrary_Variable_Name';
    my $config_key      = $auth_name . $variable_wanted;
    my $mock_config
        = { $config_key => 'Value for this configuration variable.', };
    my $r = set_up( $auth_name, $mock_config );

    is( Apache2::AuthCookieDBI::_dir_config_var( $r, $variable_wanted ),
        $mock_config->{$config_key},
        '_dir_config_var() passes correct args to $r->dir_config()'
    );
    return 1;
}

sub test_defined_or_empty {
    my $user = 'matisse';
    my $password;
    my @other_stuff = qw( a b c );
    is( Apache2::AuthCookieDBI::_defined_or_empty(
            $user, $password, @other_stuff
        ),
        5,
        '_defined_or_empty returns expected number of items.'
    );
    return 1;
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
        my $mock_crypt_text
            = Apache2::AuthCookieDBI::_encrypt_session_key(@args);

        is( $mock_crypt_text,
            $expected->{$encryption_type},
            "_encrypt_session_key() using $encryption_type"
        );
    }
    return 1;
}

sub test_get_cipher_type {

    # ( $dbi_encryption_type, $auth_name, $secret_key )
    my $auth_name  = 'Sample Auth Name';
    my $secret_key = 'Sample Secret Key String';
    my @test_cases = (
        {   dbi_encryption_type  => 'des',
            expected_cipher_type => 'DES',
        },
        {   dbi_encryption_type  => 'idea',
            expected_cipher_type => 'IDEA',
        },
        {   dbi_encryption_type  => 'blowfish',
            expected_cipher_type => 'Blowfish',
        },
        {   dbi_encryption_type  => 'blowfish_pp',
            expected_cipher_type => 'Blowfish_PP',
        },
        {   dbi_encryption_type  => 'BLOWFISH_PP', # verify case-insensitive
            expected_cipher_type => 'Blowfish_PP',
        },
    );
    foreach my $case (@test_cases) {
        my $dbi_encryption_type = $case->{'dbi_encryption_type'};
        my $mock_cbc
            = Apache2::AuthCookieDBI::_get_cipher_type( $dbi_encryption_type,
            $auth_name, $secret_key, );
        Test::More::is( $mock_cbc->{'secret_key'},
            $secret_key,
            "_get_cipher_type() for $dbi_encryption_type - secret_key" );

        my $expected_cipher_type = $case->{'expected_cipher_type'};
        Test::More::is( $mock_cbc->{'cipher_type'},
            $expected_cipher_type,
            "_get_cipher_type() for $dbi_encryption_type - cipher_type" );

        my $second_mock_from_same_args
            = Apache2::AuthCookieDBI::_get_cipher_type( $dbi_encryption_type,
            $auth_name, $secret_key, );

        Test::More::is( $second_mock_from_same_args, $mock_cbc,
            "_get_cipher_type($dbi_encryption_type,$auth_name, $secret_key) cached CBC object"
        );
    }

    my $unsupported_type = 'BunnyRabbits';
    eval {
        Apache2::AuthCookieDBI::_get_cipher_type( $unsupported_type, $auth_name,
            $secret_key, );
    };
    Test::More::like(
        $EVAL_ERROR,
        qr/Unsupported encryption type: '$unsupported_type'/,
        '_get_cipher_type() throws exception on unsupported encryption type.'
    );
    return 1;
}

sub test__dbi_connect {
    my $auth_name   = 'testing__dbi_connect';

    my %mock_config = (
        "${auth_name}DBI_DSN"             => 'test DBI_DSN',
        "${auth_name}DBI_User"            => 'test DBI_User',
        "${auth_name}DBI_Password"        => 'test DBI_Password',
        "${auth_name}DBI_SecretKey"       => 'test DBI_SecretKey',
    );
    my $r = set_up( $auth_name, \%mock_config );
    
    my $mock_dbh = Apache2::AuthCookieDBI::_dbi_connect($r);
    my $expected = [
                     $mock_config{"${auth_name}DBI_DSN"},
                     $mock_config{"${auth_name}DBI_User"},
                     $mock_config{"${auth_name}DBI_Password"}
                    ];
    Test::More::is_deeply($mock_dbh->{'connect_cached_args'},
    $expected, '_dbi_connect() calls connect_cached() with expected arguments.')
    || Test::More::diag( 'Sensor object contains: ', Data::Dumper::Dumper($mock_dbh));

    Test::More::is_deeply($r->{'_error_messages'}, [], '_dbi_connect() - no unexpected errors.');
    
    my @expected_errors = (
        qq{connect to test DBI_DSN for auth realm $auth_name},
        q{_dbi_connect called in main::test__dbi_connect},
    );
    {
        no warnings qw(once);
        local $DBI::CONNECT_CACHED_FORCE_FAIL = 1;
        Apache2::AuthCookieDBI::_dbi_connect($r);
    }
    my @got_errors = @{$r->{'_error_messages'}};
    my $got_failures = 0;
    for ( my $i=0; $i <= $#expected_errors; $i++) {
        my $got = $got_errors[$i];
        my $expected_regex = qr/$expected_errors[$i]/;
        Test::More::like($got,
                         $expected_regex,
                         qq{_dbi_connect() logs error for "$expected_errors[$i]"}
                         ) || $got_failures++;
    }
  
    if ($got_failures) {
        Test::More::diag('Mock request object contains: ', Data::Dumper::Dumper($r));
    }
    return 1;
}
