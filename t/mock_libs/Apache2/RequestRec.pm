package Apache2::RequestRec;
use strict;
use warnings;

# Mock library for testing only.

sub new {
    my ($class, %args ) = @_;
    my $self = \%args;
    bless $self, $class;
    return $self;
}

sub auth_name {
    my ($self) = @_;
    return $self->{auth_name};
}

# The real dir_config() returns the *value* of the requested variable.
# This test version just returns the name of the requetsed variable,
# so we can test if the right one is requested.
sub dir_config {
    my ($self,$name_of_requested_variable) = @_;
    return $name_of_requested_variable;
}

1;