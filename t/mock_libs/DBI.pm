# $Header: /Users/matisse/Desktop/CVS2GIT/matisse.net.cvs/Apache-AuthCookieDBI/t/mock_libs/DBI.pm,v 1.1 2007/02/04 19:45:10 matisse Exp $
# $Revision: 1.1 $
# $Author: matisse $
# $Source: /Users/matisse/Desktop/CVS2GIT/matisse.net.cvs/Apache-AuthCookieDBI/t/mock_libs/DBI.pm,v $
# $Date: 2007/02/04 19:45:10 $
###############################################################################

#  Mock class - for testing only

package DBI;
use strict;
use warnings;

#warn 'Loading mock library ' . __FILE__;
my $MOCK_DBH_CLASS = 'DBI::Mock::dbh';

my %ARGS = ();

sub connect_cached {
    my ( $class, @args ) = @_;
    my $fake_dbh = {};
    bless $fake_dbh, $MOCK_DBH_CLASS;
    $ARGS{$fake_dbh} = \@args;
    return $fake_dbh;
}

1;
