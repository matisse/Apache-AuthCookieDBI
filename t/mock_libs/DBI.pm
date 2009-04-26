# $Header: /Users/matisse/Desktop/CVS2GIT/matisse.net.cvs/Apache-AuthCookieDBI/t/mock_libs/DBI.pm,v 1.2 2009/04/26 17:32:37 matisse Exp $
# $Revision: 1.2 $
# $Author: matisse $
# $Source: /Users/matisse/Desktop/CVS2GIT/matisse.net.cvs/Apache-AuthCookieDBI/t/mock_libs/DBI.pm,v $
# $Date: 2009/04/26 17:32:37 $
###############################################################################

#  Mock class - for testing only

package DBI;
use strict;
use warnings;

#warn 'Loading mock library ' . __FILE__;
my $MOCK_DBH_CLASS = 'DBI::Mock::dbh';

our $CONNECT_CACHED_FORCE_FAIL;

sub connect_cached {
    my ( $class, @args ) = @_;
    
    if ($CONNECT_CACHED_FORCE_FAIL) {
        return;
    }

    my $fake_dbh = {};
    bless $fake_dbh, $MOCK_DBH_CLASS;
    $fake_dbh->{'connect_cached_args'} = \@args;
    
    return $fake_dbh;
}

1;
