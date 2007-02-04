package Apache2::RequestRec;
use strict;
use warnings;

# Mock library for testing only.

sub new {
    my ($class, %args ) = @_;
    my $self = \%args;
    bless $self, $class;
    $self->{_error_messages} = [];
    return $self;
}

sub auth_name {
    my ($self) = @_;
    return $self->{auth_name};
}

sub dir_config {
    my ($self,$name_of_requested_variable) = @_;
    my $mock_config = $self->{mock_config};
    return $mock_config->{$name_of_requested_variable};
}

sub log_error {
    my ($self, @args) = @_;
    if (@args) {
        my $message = join("\t", @args);
        push @{ $self->{_error_messages} }, $message;
    }
    return $self->{_error_messages};
}

sub uri {
    return 'test_uri';
}

1;