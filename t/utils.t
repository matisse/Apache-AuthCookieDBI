use strict;
use warnings;
use FindBin qw($Bin);
use lib "$Bin/mock_libs";
use Crypt::CBC; # from mocks
use Digest::MD5 qw( md5_hex ); # from mocks

use Test::More tests => 10;

my $PACKAGE      = 'Apache2::AuthCookieDBI';
my $EMPTY_STRING = q{};

use_ok($PACKAGE);
test_defined_or_empty();
test_encrypt_session_key();
test_dir_config_var();
test_authen_ses_key();

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
        $auth_name .
          'DBI_DSN' => 'test DSN',
        $auth_name .
          'DBI_SecretKey' => $secret_key,
        $auth_name .
          'DBI_User' => $auth_name,
        $auth_name .
          'DBI_Password' => 'test DBI password',
        $auth_name .
          'DBI_UsersTable' => 'users',
        $auth_name .
          'DBI_UserField' => 'user',
        $auth_name .
          'DBI_passwordfield' => 'password',
        $auth_name .
          'DBI_crypttype' => 'none',
        $auth_name .
          'DBI_groupstable' => 'groups',
        $auth_name .
          'DBI_groupfield' => 'grp',
        $auth_name .
          'DBI_groupuserfield' => 'user',
        $auth_name .
          'DBI_encryptiontype' => 'none',
        $auth_name .
          'DBI_sessionlifetime' => '00-24-00-00',
        $auth_name . 'DBI_sessionmodule' => 'none',
    };
    my $r           = set_up( $auth_name, $mock_config );
    my $expected_user        = 'expected_username';
    my $issue_time  = '2006-02-04-10-34-23';
    my $expire_time = '9999-02-04-10-45-00';
    my $session_id  = 'test_session_id';
    my $extra_session_info = 'extra:info';
    my $hashed_string = 'bad-key-stored-in-ticket';   # not a 32 char hex string
    my $encrypted_session_key = join( q{:},
        $expected_user, $issue_time, $expire_time, $session_id, $hashed_string );

    Apache2::AuthCookieDBI->authen_ses_key( $r, $encrypted_session_key );
    like(
        $r->log_error->[-1],
        qr/ bad \s encrypted \s session_key /xm,
        'authen_ses_key() on bad encrypted key'
    );

    $r = set_up( $auth_name, $mock_config );

    my $seperator = q{:};
    my $public_part = join($seperator ,
        $expected_user,       $issue_time, $expire_time,
        $session_id, $extra_session_info);
        
    my $plaintext_key = join( $seperator, $public_part, $secret_key );

    my $md5_hash = md5_hex($plaintext_key);

    $hashed_string = md5_hex( join( $seperator, $secret_key, $md5_hash ) );

    $encrypted_session_key = join( q{:}, $public_part, $hashed_string );

    my $got_user =
      Apache2::AuthCookieDBI->authen_ses_key( $r, $encrypted_session_key );
    is( $got_user, $expected_user, 'authen_ses_key() on plaintext key' )
      || diag join( "\n", @{ $r->log_error() } );
    return 1;
}

sub test_dir_config_var {
    my $auth_name       = 'testing_dir_config_var';
    my $variable_wanted = 'Arbitrary_Variable_Name';
    my $config_key      = $auth_name . $variable_wanted;
    my $mock_config =
      { $config_key => 'Value for this configuration variable.', };
    my $r = set_up( $auth_name, $mock_config );

    is(
        Apache2::AuthCookieDBI::_dir_config_var( $r, $variable_wanted ),
        $mock_config->{$config_key},
        '_dir_config_var() passes correct args to $r->dir_config()'
    );
    return 1;
}

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
        my $mock_crypt_text =
          Apache2::AuthCookieDBI::_encrypt_session_key(@args);

        is(
            $mock_crypt_text,
            $expected->{$encryption_type},
            "_encrypt_session_key() using $encryption_type"
        );
    }
    return 1;
}
