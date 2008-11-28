#===============================================================================
#
# $Id: AuthCookieDBI.pm,v 1.44 2008/11/28 23:44:31 matisse Exp $
#
# Apache2::AuthCookieDBI
#
# An AuthCookie module backed by a DBI database.
#
# See end of this file for Copyright notices.
#
# Author:  Jacob Davies <jacob@well.com>
# Maintainer: Matisse Enzer <matisse@matisse.net> (as of version 2.0)
#
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#===============================================================================

package Apache2::AuthCookieDBI;

use strict;
use warnings;
use 5.004;
use vars qw( $VERSION );
$VERSION = '2.11';

use Apache2::AuthCookie;
use base qw( Apache2::AuthCookie );

use Apache2::RequestRec;
use Apache::DBI;
use Apache2::Const -compile => qw( OK HTTP_FORBIDDEN );
use Apache2::ServerUtil;
use Digest::MD5 qw( md5_hex );
use Date::Calc qw( Today_and_Now Add_Delta_DHMS );

# Also uses Crypt::CBC if you're using encrypted cookies.
# Also uses Apache2::Session if you're using sessions.
use English qw(-no_match_vars);

#===============================================================================
# FILE (LEXICAL)  G L O B A L S
#===============================================================================

my %CIPHERS = ();

# Stores Cipher::CBC objects in $CIPHERS{ idea:AuthName },
# $CIPHERS{ des:AuthName } etc.

my $EMPTY_STRING = q{};

my $WHITESPACE_REGEX                      = qr/ \s+ /mx;
my $HEX_STRING_REGEX                      = qr/ \A [0-9a-fA-F] \z /mx;
my $THIRTY_TWO_CHARACTER_HEX_STRING_REGEX = qr/  \A [0-9a-fA-F]{32} \z /mx;
my $DATE_TIME_STRING_REGEX = qr/ \A \d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2} \z /mx;
my $PERCENT_ENCODED_STRING_REGEX = qr/ \A [a-zA-Z0-9_\%]+ \z /mx;
my $COLON_REGEX                  = qr/ : /mx;
my $HYPHEN_REGEX                 = qr/ - /mx;

#===============================================================================
# P E R L D O C
#===============================================================================

=head1 NAME

Apache2::AuthCookieDBI - An AuthCookie module backed by a DBI database.

=head1 VERSION

    This is version 2.10

=head1 COMPATIBILITY

Starting with version 2.03 the module is in the Apache2::* namespace,
L<Apache2::AuthCookieDBI>.  For F<mod_perl1> versions
there is: L<Apache::AuthCookieDBI>

=head1 SYNOPSIS

    # In httpd.conf or .htaccess
        
    PerlModule Apache2::AuthCookieDBI
    PerlSetVar WhatEverPath /
    PerlSetVar WhatEverLoginScript /login.pl

    # Optional, to share tickets between servers.
    PerlSetVar WhatEverDomain .domain.com
    
    # These must be set
    PerlSetVar WhatEverDBI_DSN "DBI:mysql:database=test"
    PerlSetVar WhatEverDBI_SecretKey "489e5eaad8b3208f9ad8792ef4afca73598ae666b0206a9c92ac877e73ce835c"

    # These are optional, the module sets sensible defaults.
    PerlSetVar WhatEverDBI_User "nobody"
    PerlSetVar WhatEverDBI_Password "password"
    PerlSetVar WhatEverDBI_UsersTable "users"
    PerlSetVar WhatEverDBI_UserField "user"
    PerlSetVar WhatEverDBI_PasswordField "password"
    PerlSetVar WhatEverDBI_CryptType "none"
    PerlSetVar WhatEverDBI_GroupsTable "groups"
    PerlSetVar WhatEverDBI_GroupField "grp"
    PerlSetVar WhatEverDBI_GroupUserField "user"
    PerlSetVar WhatEverDBI_EncryptionType "none"
    PerlSetVar WhatEverDBI_SessionLifetime 00-24-00-00

    # Protected by AuthCookieDBI.
    <Directory /www/domain.com/authcookiedbi>
        AuthType Apache2::AuthCookieDBI
        AuthName WhatEver
        PerlAuthenHandler Apache2::AuthCookieDBI->authenticate
        PerlAuthzHandler Apache2::AuthCookieDBI->authorize
        require valid-user
        # or you can require users:
        require user jacob
        # You can optionally require groups.
        require group system
    </Directory>

    # Login location.
    <Files LOGIN>
        AuthType Apache2::AuthCookieDBI
        AuthName WhatEver
        SetHandler perl-script
        PerlHandler Apache2::AuthCookieDBI->login
    </Files>

=head1 DESCRIPTION

This module is an authentication handler that uses the basic mechanism provided
by Apache2::AuthCookie with a DBI database for ticket-based protection.  It
is based on two tokens being provided, a username and password, which can
be any strings (there are no illegal characters for either).  The username is
used to set the remote user as if Basic Authentication was used.

On an attempt to access a protected location without a valid cookie being
provided, the module prints an HTML login form (produced by a CGI or any
other handler; this can be a static file if you want to always send people
to the same entry page when they log in).  This login form has fields for
username and password.  On submitting it, the username and password are looked
up in the DBI database.  The supplied password is checked against the password
in the database; the password in the database can be plaintext, or a crypt()
or md5_hex() checksum of the password.  If this succeeds, the user is issued
a ticket.  This ticket contains the username, an issue time, an expire time,
and an MD5 checksum of those and a secret key for the server.  It can
optionally be encrypted before returning it to the client in the cookie;
encryption is only useful for preventing the client from seeing the expire
time.  If you wish to protect passwords in transport, use an SSL-encrypted
connection.  The ticket is given in a cookie that the browser stores.

After a login the user is redirected to the location they originally wished
to view (or to a fixed page if the login "script" was really a static file).

On this access and any subsequent attempt to access a protected document, the
browser returns the ticket to the server.  The server unencrypts it if
encrypted tickets are enabled, then extracts the username, issue time, expire
time and checksum.  A new checksum is calculated of the username, issue time,
expire time and the secret key again; if it agrees with the checksum that
the client supplied, we know that the data has not been tampered with.  We
next check that the expire time has not passed.  If not, the ticket is still
good, so we set the username.

Authorization checks then check that any "require valid-user" or "require
user jacob" settings are passed.  Finally, if a "require group foo" directive
was given, the module will look up the username in a groups database and
check that the user is a member of one of the groups listed.  If all these
checks pass, the document requested is displayed.

If a ticket has expired or is otherwise invalid it is cleared in the browser
and the login form is shown again.

=cut

#===============================================================================
# P R I V A T E   F U N C T I O N S
#===============================================================================

# Get the cipher from the cache, or create a new one if the
# cached cipher hasn't been created, & decrypt the session key.
sub _get_cipher_type {
    my ( $dbi_encryption_type, $auth_name, $secret_key ) = @_;
    $dbi_encryption_type = lc $dbi_encryption_type;

    my %cipher_type = (
        des => sub {
            return $CIPHERS{"des:$auth_name"}
              || Crypt::CBC->new( $secret_key, 'DES' );
        },
        idea => sub {
            return $CIPHERS{"idea:$auth_name"}
              || Crypt::CBC->new( $secret_key, 'IDEA' );
        },
        blowfish => sub {
            return $CIPHERS{"blowfish:$auth_name"}
              || Crypt::CBC->new( $secret_key, 'Blowfish' );
        },
        blowfish_pp => sub {
            return $CIPHERS{"blowfish_pp:$auth_name"}
              || Crypt::CBC->new( $secret_key, 'Blowfish_PP' );
        },
    );
    my $type = $cipher_type{$dbi_encryption_type}->();
    return $type;
}

sub _encrypt_session_key {
    my $session_key         = shift;
    my $secret_key          = shift;
    my $auth_name           = shift;
    my $dbi_encryption_type = lc shift;

    my %encryption_handlers = (
        none => sub { return $session_key },
        des  => sub {
            $CIPHERS{"des:$auth_name"} ||=
              Crypt::CBC->new( $secret_key, 'DES' );
            return $CIPHERS{"des:$auth_name"}->encrypt_hex($session_key);
        },
        idea => sub {
            $CIPHERS{"idea:$auth_name"} ||=
              Crypt::CBC->new( $secret_key, 'IDEA' );
            return $CIPHERS{"idea:$auth_name"}->encrypt_hex($session_key);
        },
        blowfish => sub {
            $CIPHERS{"blowfish:$auth_name"} ||=
              Crypt::CBC->new( $secret_key, 'Blowfish' );
            return $CIPHERS{"blowfish:$auth_name"}->encrypt_hex($session_key);
        },
        blowfish_pp => sub {
            $CIPHERS{"blowfish_pp:$auth_name"} ||=
              Crypt::CBC->new( $secret_key, 'Blowfish_PP' );
            return $CIPHERS{"blowfish_pp:$auth_name"}
              ->encrypt_hex($session_key);
        },
    );
    my $encrypted_key = $encryption_handlers{$dbi_encryption_type}->();
    return $encrypted_key;
}

#-------------------------------------------------------------------------------
# _log_not_set -- Log that a particular authentication variable was not set.

sub _log_not_set {
    my ( $r, $variable ) = @_;
    my $auth_name = $r->auth_name;
    return $r->log_error(
        "Apache2::AuthCookieDBI: $variable not set for auth realm
$auth_name", $r->uri
    );
}

#-------------------------------------------------------------------------------
# _dir_config_var -- Get a particular authentication variable.

sub _dir_config_var {
    my ( $r, $variable ) = @_;
    my $auth_name = $r->auth_name;
    return $r->dir_config("$auth_name$variable");
}

#-------------------------------------------------------------------------------
# _dbi_config_vars -- Gets the config variables from the dir_config and logs
# errors if required fields were not set, returns undef if any of the fields
# had errors or a hash of the values if they were all OK.  Takes a request
# object.

my %CONFIG_DEFAULT = (
    DBI_DSN             => undef,
    DBI_SecretKey       => undef,
    DBI_User            => undef,
    DBI_Password        => undef,
    DBI_UsersTable      => 'users',
    DBI_UserField       => 'user',
    DBI_passwordfield   => 'password',
    DBI_crypttype       => 'none',
    DBI_groupstable     => 'groups',
    DBI_groupfield      => 'grp',
    DBI_groupuserfield  => 'user',
    DBI_encryptiontype  => 'none',
    DBI_sessionlifetime => '00-24-00-00',
    DBI_sessionmodule   => 'none',
);

sub _dbi_config_vars {
    my ($r) = @_;

    my %c;    # config variables hash
    foreach my $variable ( keys %CONFIG_DEFAULT ) {
        my $value_from_config = _dir_config_var( $r, $variable );
        $c{$variable} =
          defined $value_from_config
          ? $value_from_config
          : $CONFIG_DEFAULT{$variable};
        if ( !defined $c{$variable} ) {
            _log_not_set( $r, $variable );
        }
    }

    # If we used encryption we need to pull in Crypt::CBC.
    if ( $c{DBI_encryptiontype} ne 'none' ) {
        require Crypt::CBC;
    }

    return %c;
}

=head1 APACHE CONFIGURATION DIRECTIVES

All configuration directives for this module are passed in PerlSetVars.  These
PerlSetVars must begin with the AuthName that you are describing, so if your
AuthName is PrivateBankingSystem they will look like:

    PerlSetVar PrivateBankingSystemDBI_DSN "DBI:mysql:database=banking"

See also L<Apache2::Authcookie> for the directives required for any kind
of Apache2::AuthCookie-based authentication system.

In the following descriptions, replace "WhatEver" with your particular
AuthName.  The available configuration directives are as follows:

=over 4

=item C<WhatEverDBI_DSN>

Specifies the DSN for DBI for the database you wish to connect to retrieve
user information.  This is required and has no default value.

=item C<WhateverDBI_SecretKey>

Specifies the secret key for this auth scheme.  This should be a long
random string.  This should be secret; either make the httpd.conf file
only readable by root, or put the PerlSetVar in a file only readable by
root and include it.

This is required and has no default value.
(NOTE: In AuthCookieDBI versions 1.22 and earlier the secret key either could be
or was required to be in a seperate file with the path configured with
PerlSetVar WhateverDBI_SecretKeyFile, as of version 2.0 this is not possible, you
must put the secret key in the Apache configuration directly, either in the main
httpd.conf file or in an included file.  You might wish to make the file not
world-readable. Also, make sure that the Perl environment variables are
not publically available, for example via the /perl-status handler.)
See also L</"COMPATIBILITY"> in this man page.


=item C<WhatEverDBI_User>

The user to log into the database as.  This is not required and
defaults to undef.

=item C<WhatEverDBI_Password>

The password to use to access the database.  This is not required
and defaults to undef.

Make sure that the Perl environment variables are
not publically available, for example via the /perl-status handler since the
password could be exposed.

=item C<WhatEverDBI_UsersTable>

The table that user names and passwords are stored in.  This is not
required and defaults to 'users'.

=item C<WhatEverDBI_UserField>

The field in the above table that has the user name.  This is not
required and defaults to 'user'.

=item C<WhatEverDBI_PasswordField>

The field in the above table that has the password.  This is not
required and defaults to 'password'.

=item C<WhatEverDBI_CryptType>

What kind of hashing is used on the password field in the database.  This can
be 'none', 'crypt', or 'md5'.  This is not required and defaults to 'none'.

=item C<WhatEverDBI_GroupsTable>

The table that has the user / group information.  This is not required and
defaults to 'groups'.

=item C<WhatEverDBI_GroupField>

The field in the above table that has the group name.  This is not required
and defaults to 'grp' (to prevent conflicts with the SQL reserved word 'group').

=item C<WhatEverDBI_GroupUserField>

The field in the above table that has the user name.  This is not required
and defaults to 'user'.

=item C<WhatEverDBI_EncryptionType>

What kind of encryption to use to prevent the user from looking at the fields
in the ticket we give them.  This is almost completely useless, so don't
switch it on unless you really know you need it.  It does not provide any
protection of the password in transport; use SSL for that.  It can be 'none',
'des', 'idea', 'blowfish', or 'blowfish_pp'.

This is not required and defaults to 'none'.

=item C<WhatEverDBI_SessionLifetime>

How long tickets are good for after being issued.  Note that presently
Apache2::AuthCookie does not set a client-side expire time, which means that
most clients will only keep the cookie until the user quits the browser.
However, if you wish to force people to log in again sooner than that, set
this value.  This can be 'forever' or a life time specified as:

    DD-hh-mm-ss -- Days, hours, minute and seconds to live.

This is not required and defaults to '00-24-00-00' or 24 hours.

=item C<WhatEverDBI_SessionModule>

Which Apache2::Session module to use for persistent sessions.
For example, a value could be "Apache2::Session::MySQL".  The DSN will
be the same as used for authentication.  The session created will be
stored in $r->pnotes( WhatEver ).

If you use this, you should put:

    PerlModule Apache2::Session::MySQL

(or whatever the name of your session module is) in your httpd.conf file,
so it is loaded.

If you are using this directive, you can timeout a session on the server side
by deleting the user's session.  Authentication will then fail for them.

This is not required and defaults to none, meaning no session objects will
be created.

=cut

#-------------------------------------------------------------------------------
# _now_year_month_day_hour_minute_second -- Return a string with the time in
# this order separated by dashes.

sub _now_year_month_day_hour_minute_second {
    return sprintf '%04d-%02d-%02d-%02d-%02d-%02d', Today_and_Now;
}

sub _check_password {
    my $password         = shift;
    my $crypted_password = shift;
    my $crypt_type       = shift;
    my %password_checker = (
        none => sub { return $password eq $crypted_password; },
        'crypt' => sub {
            my $salt = substr $crypted_password, 0, 2;
            return crypt( $password, $salt ) eq $crypted_password;
        },
        md5 => sub { return md5_hex($password) eq $crypted_password; },
    );
    return $password_checker{$crypt_type}->();
}

#-------------------------------------------------------------------------------
# _percent_encode -- Percent-encode (like URI encoding) any non-alphanumberics
# in the supplied string.

sub _percent_encode {
    my ($str) = @_;
    my $not_a_word = qr/ ( \W ) /x;
    $str =~ s/$not_a_word/ uc sprintf '%%%02x', ord $1 /xmeg;
    return $str;
}

#-------------------------------------------------------------------------------
# _percent_decode -- Percent-decode (like URI decoding) any %XX sequences in
# the supplied string.

sub _percent_decode {
    my ($str) = @_;
    my $percent_hex_string_regex = qr/ %([0-9a-fA-F]{2}) /x;
    $str =~ s/$percent_hex_string_regex/ pack( "c",hex( $1 ) ) /xmge;
    return $str;
}

#-------------------------------------------------------------------------------
# _dbi_connect -- Get a database handle.

sub _dbi_connect {
    my ($r) = @_;
    my %c = _dbi_config_vars $r;

    # get the crypted password from the users database for this user.
    my $dbh =
      DBI->connect_cached( $c{DBI_DSN}, $c{DBI_user}, $c{DBI_password} );
    if ( defined $dbh ) {
        return $dbh;
    }
    else {
        my $auth_name = $r->auth_name;
        $r->log_error(
"Apache2::AuthCookieDBI: couldn't connect to $c{ DBI_DSN } for auth realm $auth_name",
            $r->uri
        );
        my ( $pkg, $file, $line, $sub ) = caller(1);
        $r->log_error(
            "Apache2::AuthCookieDBI::_dbi_connect called in $sub at line $line"
        );
        return;
    }
}

#-------------------------------------------------------------------------------
# _get_crypted_password -- Get the users' password from the database

sub _get_crypted_password {
    my ( $r, $user, $c ) = @_;
    my $dbh = _dbi_connect($r) || return;

    my $sth = $dbh->prepare_cached( <<"EOS" );
SELECT $c->{ DBI_passwordfield }
FROM $c->{ DBI_userstable }
WHERE $c->{ DBI_userfield } = ?
EOS
    $sth->execute($user);
    my ($crypted_password) = $sth->fetchrow_array;
    if ( defined $crypted_password ) {
        return $crypted_password;
    }
    else {
        my $auth_name = $r->auth_name;
        $r->log_error(
"Apache2::AuthCookieDBI: couldn't select password from $c->{ DBI_DSN }, $c->{ DBI_userstable }, $c->{ DBI_userfield } for user $user for auth realm $auth_name",
            $r->uri
        );
        return;
    }
}

sub _get_new_session {
    my $r              = shift;
    my $user           = shift;
    my $auth_name      = shift;
    my $session_module = shift;
    my $extra_data     = shift;

    my $dbh = _dbi_connect($r);
    my %session;
    tie %session, $session_module, undef,
      +{
        Handle     => $dbh,
        LockHandle => $dbh,
      };

    $session{user}       = $user;
    $session{extra_data} = $extra_data;
    return \%session;
}

# Takes a list and returns a list of the same size.
# Any element in the inputs that is defined is returned unchanged. Elements that
# were undef are returned as empty strings.
sub _defined_or_empty {
    my @args        = @_;
    my @all_defined = ();
    foreach my $arg (@args) {
        if ( defined $arg ) {
            push @all_defined, $arg;
        }
        else {
            push @all_defined, $EMPTY_STRING;
        }
    }
    return @all_defined;
}

#===============================================================================
# P U B L I C   F U N C T I O N S
#===============================================================================

=head1 SUBCLASSING

You can subclass this module to override public functions and change
their behaviour.

=over 4

=item C<extra_session_info()>

This method returns extra fields to add to the session key.
It should return a string consisting of ":field1:field2:field3"
(where each field is preceded by a colon).

The default implementation returns an empty string.

=back

=cut

sub extra_session_info {
    my ( $self, $r, @credentials ) = @_;

    return $EMPTY_STRING;
}

#-------------------------------------------------------------------------------
# Take the credentials for a user and check that they match; if so, return
# a new session key for this user that can be stored in the cookie.
# If there is a problem, return a bogus session key.

sub authen_cred {
    my ( $self, $r,        @credentials ) = @_;
    my ( $user, $password, @extra_data )  = @credentials;
    my $auth_name = $r->auth_name;
    ( $user, $password ) = _defined_or_empty( $user, $password );

    if ( !length $user ) {
        $r->log_error(
"Apache2::AuthCookieDBI: no username supplied for auth realm $auth_name",
            $r->uri
        );
        return;
    }

    if ( !length $password ) {
        $r->log_error(
"Apache2::AuthCookieDBI: no password supplied for auth realm $auth_name",
            $r->uri
        );
        return;
    }

    # get the configuration information.
    my %c = _dbi_config_vars($r);

    # get the crypted password from the users database for this user.
    my $crypted_password = _get_crypted_password( $r, $user, \%c );

    # now return unless the passwords match.
    my $crypt_type = lc $c{DBI_crypttype};
    if ( !_check_password( $password, $crypted_password, $crypt_type ) ) {
        $r->log_error(
"Apache2::AuthCookieDBI: $crypt_type passwords didn't match for user $user for auth realm $auth_name",
            $r->uri
        );
        return;
    }

    # Create the expire time for the ticket.
    my $expire_time = _get_expire_time( $c{DBI_sessionlifetime} );

    # Now we need to %-encode non-alphanumberics in the username so we
    # can stick it in the cookie safely.
    my $enc_user = _percent_encode($user);

    # If we are using sessions, we create a new session for this login.
    my $session_id = $EMPTY_STRING;
    if ( $c{DBI_sessionmodule} ne 'none' ) {
        my $session =
          _get_new_session( $r, $user, $auth_name, $c{DBI_sessionmodule},
            \@extra_data );
        $r->pnotes( $auth_name, $session );
        $session_id = $session->{_session_id};
    }

    # OK, now we stick the username and the current time and the expire
    # time and the session id (if any) together to make the public part
    # of the session key:
    my $current_time = _now_year_month_day_hour_minute_second;
    my $public_part  = "$enc_user:$current_time:$expire_time:$session_id";
    $public_part .= $self->extra_session_info( $r, @credentials );

    # Now we calculate the hash of this and the secret key and then
    # calculate the hash of *that* and the secret key again.
    my $secretkey = $c{DBI_SecretKey};
    if ( !defined $secretkey ) {
        $r->log_error(
"Apache2::AuthCookieDBI: didn't have the secret key for auth realm $auth_name",
            $r->uri
        );
        return;
    }
    my $hash =
      md5_hex( join q{:}, $secretkey,
        md5_hex( join q{:}, $public_part, $secretkey ) );

    # Now we add this hash to the end of the public part.
    my $session_key = "$public_part:$hash";

    # Now we encrypt this and return it.
    my $encrypted_session_key =
      _encrypt_session_key( $session_key, $secretkey, $auth_name,
        $c{DBI_encryptiontype} );
    return $encrypted_session_key;
}

#-------------------------------------------------------------------------------
# Take a session key and check that it is still valid; if so, return the user.

sub authen_ses_key {
    my ( $self, $r, $encrypted_session_key ) = @_;

    my $auth_name = $r->auth_name;

    # Get the configuration information.
    my %c = _dbi_config_vars($r);

    # Get the secret key.
    my $secret_key = $c{DBI_SecretKey};
    if ( !defined $secret_key ) {
        $r->log_error(
"Apache2::AuthCookieDBI: didn't have the secret key from for auth realm $auth_name",
            $r->uri
        );
        return;
    }

    # Decrypt the session key.
    my $session_key;
    if ( $c{DBI_encryptiontype} eq 'none' ) {
        $session_key = $encrypted_session_key;
    }
    else {

        # Check that this looks like an encrypted hex-encoded string.
        if ( $encrypted_session_key !~ $HEX_STRING_REGEX ) {
            $r->log_error(
"Apache2::AuthCookieDBI: encrypted session key $encrypted_session_key doesn't look like it's properly hex-encoded for auth realm $auth_name",
                $r->uri
            );
            return;
        }

        my $cipher =
          _get_cipher_type( $c{DBI_encryptiontype}, $auth_name, $secret_key );
        if ( !$cipher ) {
            $r->log_error(
"Apache2::AuthCookieDBI: unknown encryption type $c{ DBI_encryptiontype } for auth realm $auth_name",
                $r->uri
            );
            return;
        }
        $session_key = $cipher->decrypt_hex($encrypted_session_key);
    }

    # Break up the session key.
    my (
        $enc_user,   $issue_time,    $expire_time,
        $session_id, @rest
    ) = split $COLON_REGEX, $session_key;
    my $hashed_string = pop @rest;

    # Let's check that we got passed sensible values in the cookie.
    ($enc_user) = _defined_or_empty($enc_user);
    if ( $enc_user !~ $PERCENT_ENCODED_STRING_REGEX ) {
        $r->log_error(
"Apache2::AuthCookieDBI: bad percent-encoded user '$enc_user' recovered from session ticket for auth_realm '$auth_name'",
            $r->uri
        );
        return;
    }

    # decode the user
    my $user = _percent_decode($enc_user);

    ($issue_time) = _defined_or_empty($issue_time);
    if ( $issue_time !~ $DATE_TIME_STRING_REGEX ) {
        $r->log_error(
"Apache2::AuthCookieDBI: bad issue time '$issue_time' recovered from ticket for user $user for auth_realm $auth_name",
            $r->uri
        );
        return;
    }
    
    ($expire_time) = _defined_or_empty($expire_time);
    if ( $expire_time !~ $DATE_TIME_STRING_REGEX ) {
        $r->log_error(
"Apache2::AuthCookieDBI: bad expire time $expire_time recovered from ticket for user $user for auth_realm $auth_name",
            $r->uri
        );
        return;
    }
    if ( $hashed_string !~ $THIRTY_TWO_CHARACTER_HEX_STRING_REGEX ) {
        $r->log_error(
"Apache2::AuthCookieDBI: bad encrypted session_key $hashed_string recovered from ticket for user $user for auth_realm $auth_name",
            $r->uri
        );
        return;
    }

    # If we're using a session module, check that their session exist.
    if ( $c{DBI_sessionmodule} ne 'none' ) {
        my %session;
        my $dbh = _dbi_connect($r) || return;

        eval {
            tie %session, $c{DBI_sessionmodule}, $session_id,
              +{
                Handle     => $dbh,
                LockHandle => $dbh,
              };
        };
        if ($EVAL_ERROR) {
            $r->log_error(
"Apache2::AuthCookieDBI: failed to tie session hash using session id $session_id for user $user for auth_realm $auth_name, error was $@",
                $r->uri
            );
            return;
        }

        # Update a timestamp at the top level to make sure we sync.
        $session{timestamp} = _now_year_month_day_hour_minute_second;
        $r->pnotes( $auth_name, \%session );
    }

    # Calculate the hash of the user, issue time, expire_time and
    # the secret key  and the session_id and then the hash of that
    # and the secret key again.
    my $new_hash = md5_hex(
        join q{:},
        $secret_key,
        md5_hex(
            join q{:},   $enc_user, $issue_time, $expire_time,
            $session_id, @rest,     $secret_key
        )
    );

    # Compare it to the hash they gave us.
    if ( $new_hash ne $hashed_string ) {
        $r->log_error(
"Apache2::AuthCookieDBI: hash '$hashed_string' in cookie did not match calculated hash '$new_hash' of contents for user $user for auth realm $auth_name",
            $r->uri
        );
        return;
    }

    # Check that their session hasn't timed out.
    if ( _now_year_month_day_hour_minute_second gt $expire_time ) {
        $r->log_error(
"Apache:AuthCookieDBI: expire time $expire_time has passed for user $user for auth realm $auth_name",
            $r->uri
        );
        return;
    }

    # If we're being paranoid about timing-out long-lived sessions,
    # check that the issue time + the current (server-set) session lifetime
    # hasn't passed too (in case we issued long-lived session tickets
    # in the past that we want to get rid of). *** TODO ***
    # if ( lc $c{ DBI_AlwaysUseCurrentSessionLifetime } eq 'on' ) {

    # They must be okay, so return the user.
    return $user;
}

#-------------------------------------------------------------------------------
# Take a list of groups and make sure that the current remote user is a member
# of one of them.

sub group {
    my ( $self, $r, $groups ) = @_;
    my @groups = split( $WHITESPACE_REGEX, $groups );

    my $auth_name = $r->auth_name;

    # Get the configuration information.
    my %c = _dbi_config_vars $r;

    my $user = $r->user;

    # See if we have a row in the groups table for this user/group.
    my $dbh = _dbi_connect($r) || return;

    # Now loop through all the groups to see if we're a member of any:
    my $sth = $dbh->prepare_cached( <<"EOS" );
SELECT $c{ DBI_groupuserfield }
FROM $c{ DBI_groupstable }
WHERE $c{ DBI_groupfield } = ?
AND $c{ DBI_groupuserfield } = ?
EOS
    foreach my $group (@groups) {
        $sth->execute( $group, $user );
        return Apache2::Const::OK if ( $sth->fetchrow_array );
    }
    $r->log_error(
"Apache2::AuthCookieDBI: user $user was not a member of any of the required groups @groups for auth realm $auth_name",
        $r->uri
    );
    return Apache2::Const::HTTP_FORBIDDEN;
}

sub _get_expire_time {
    my $session_lifetime = shift;
    $session_lifetime = lc $session_lifetime;

    my $expire_time = $EMPTY_STRING;

    if ( $session_lifetime eq 'forever' ) {
        $expire_time =
          '9999-01-01-01-01-01'
          ,    # expire time in a zillion years if it's forever.
          return $expire_time;
    }

    my ( $deltaday, $deltahour, $deltaminute, $deltasecond ) =
      split $HYPHEN_REGEX, $session_lifetime;

    # Figure out the expire time.
    $expire_time = sprintf(
        '%04d-%02d-%02d-%02d-%02d-%02d',
        Add_Delta_DHMS( Today_and_Now, $deltaday, $deltahour,
            $deltaminute, $deltasecond
        )
    );
    return $expire_time;
}

1;

__END__

=back

=head1 DATABASE SCHEMAS

For this module to work, the database tables must be laid out at least somewhat
according to the following rules:  the user field must be a UNIQUE KEY
so there is only one row per user; the password field must be NOT NULL.  If
you're using MD5 passwords the password field must be 32 characters long to
allow enough space for the output of md5_hex().  If you're using crypt()
passwords you need to allow 13 characters.

An minimal CREATE TABLE statement might look like:

    CREATE TABLE users (
        user VARCHAR(16) PRIMARY KEY,
        password VARCHAR(32) NOT NULL
    )

For the groups table, the access table is actually going to be a join table
between the users table and a table in which there is one row per group
if you have more per-group data to store; if all you care about is group
membership though, you only need this one table.  The only constraints on
this table are that the user and group fields be NOT NULL.

A minimal CREATE TABLE statement might look like:

    CREATE TABLE groups (
        grp VARCHAR(16) NOT NULL,
        user VARCHAR(16) NOT NULL
    )

=head1 COPYRIGHT

 Copyright (C) 2002 SF Interactive.
 Copyright (C) 2003-2004 Jacob Davies
 Copyright (C) 2004-2008 Matisse Enzer

=head1 LICENSE

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

=head1 CREDITS

  Original Author: Jacob Davies
  Incomplete list of additional contributors (alphabetical by first name):
    Carl Gustafsson
    Jay Strauss
    Lance P Cleveland
    Matisse Enzer
    Nick Phillips
    William McKee

=head1 MAINTAINER

Matisse Enzer

        <matisse@cpan.org>
        
=head1 SEE ALSO

Latest version: http://search.cpan.org/perldoc?Apache2%3A%3AAuthCookieDBI

Apache2::AuthCookie(1)
Apache2::Session(1)

=head1 TODO

=over 2

=item Add a proper set of regression tests!!! Easier said than done though.

=item Refactor authen_cred() and authen_ses_key() into several smaller private methods.

=back

=cut
