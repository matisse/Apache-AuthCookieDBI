package Crypt::CBC;
use strict;
use warnings;

sub new {
    my ( $class, $secret_key, $cipher_type ) = @_;
    my $self = {
        secret_key  => $secret_key,
        cipher_type => $cipher_type,
    };
    bless $self, $class;
    return $self;
}

sub encrypt_hex {
    my ( $self, $plain_text ) = @_;
    my $mock_crypt_text = join q{:}, $self->{cipher_type}, $self->{secret_key},$plain_text;
    return $mock_crypt_text;
}

1;
