#===============================================================================
#
# $Id$
#
# Apache2_4::AuthCookieDBI
#
# A module implementing Apache 2.4.x compatibility for Apache2::AuthCookieDBI
# group-based authorizations.
#
# See end of this file for Copyright notices.
#
# Maintainer: Matisse Enzer <matisse@cpan.org> (as of version 2.0)
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

package Apache2_4::AuthCookieDBI;

# ABSTRACT: Perl group authorization for Apache 2.4.x

use strict;
use base 'Apache2::AuthCookieDBI';
use Apache2::Log;
use Apache2::Const -compile => qw(AUTHZ_GRANTED AUTHZ_DENIED AUTHZ_DENIED_NO_USER AUTHZ_GENERAL_ERROR);
use Apache::AuthCookie::Util qw(is_blank);

#===============================================================================
# FILE (LEXICAL)  G L O B A L S
#===============================================================================

our $VERSION = '2.19';
use constant LOG_TYPE_AUTHZ   => 'authorization';

#===============================================================================
# M E T H O D ( S )
#===============================================================================

sub group {
    my ($class, $r, $groups) = @_;

    my $debug = $r->dir_config("AuthCookieDebug") || 0;

    my $user = $r->user;

    $r->server->log_error("authz:start user=@{[ defined($user) ? $user : '(undef)' ]} type=$class groups=@{[ defined($groups) ? $groups : '(undef)' ]} uri=@{[ $r->uri ]}") if ($debug >= 5);

    if (is_blank($user)) {
        # User is not yet authenticated.
        return Apache2::Const::AUTHZ_DENIED_NO_USER;
    }

    if (is_blank($groups)) {
        $r->server->log_error("${class}\tno group(s) specified in \'Require group ...\' configuration for URI @{[ $r->uri ]}");
        return Apache2::Const::AUTHZ_DENIED;
    }

    my @groups = split( Apache2::AuthCookieDBI::WHITESPACE_REGEX, $groups );

    # Instead of querying the database every time, check subprocess_env
    # for AUTH_COOKIE_DBI_GROUP (set below) and utilize that to short circuit
    # the authorization.
    if ( my $cached_group = $r->subprocess_env('AUTH_COOKIE_DBI_GROUP') ) {
	$r->server->log_error("${class}\tfound cached group $cached_group") if ($debug >= 3);
	foreach my $group (@groups) {
	    if ($group eq $cached_group) {
		return Apache2::Const::AUTHZ_GRANTED;
	    }
        }
    }

    $r->server->log_error("authz user=$user type=$class group=$groups") if ($debug >= 2);

    # Get the configuration information.
    my %c = $class->_dbi_config_vars($r);

    # See if we have a row in the groups table for this user/group.
    my $dbh = $class->_dbi_connect($r) || return Apache2::Const::AUTHZ_GENERAL_ERROR;

    # Now loop through all the groups to see if we're a member of any:
    my $DBI_GroupUserField = $dbh->quote_identifier($c{'DBI_GroupUserField'});
    my $DBI_GroupsTable = $dbh->quote_identifier($c{'DBI_GroupsTable'});
    my $DBI_GroupField = $dbh->quote_identifier($c{'DBI_GroupField'});

    my $sth = $dbh->prepare_cached( <<"EOS" );
SELECT $DBI_GroupUserField
FROM $DBI_GroupsTable
WHERE $DBI_GroupField = ?
AND $DBI_GroupUserField = ?
EOS
    foreach my $group (@groups) {
	$r->server->log_error("${class}\tchecking if user $user is a member of group $group by querying $DBI_GroupsTable") if ($debug >= 4);
        $sth->execute( $group, $user );
        if ( $sth->fetchrow_array ) { # query successful; user is in group
            $sth->finish();

	    $r->server->log_error("${class}\tauthorized -- user $user is a member of group $group") if ($debug >= 4);

            # add the group to an ENV var that CGI programs can access:
            $r->subprocess_env( 'AUTH_COOKIE_DBI_GROUP' => $group );

            return Apache2::Const::AUTHZ_GRANTED;
        }
    }
    $sth->finish();

    # Log a message similar to mod_authz_user.
    my $auth_name = $r->auth_name;
    my $message
        = "${class}\tuser $user was not a member of any of the required groups @{[ join('/',@groups) ]} for auth realm $auth_name";
    $class->logger( $r, Apache2::Const::LOG_INFO, $message, $user,
        LOG_TYPE_AUTHZ, $r->uri );

    return Apache2::Const::AUTHZ_DENIED;
}

1;

__END__

#===============================================================================
# P E R L D O C
#===============================================================================

=head1 NAME

Apache2_4::AuthCookieDBI - A module implementing Apache 2.4.x compatibility
for L<Apache2::AuthCookieDBI> group-based authorizations.

=head1 SYNOPSIS

 # In httpd.conf or .htaccess:
 #   Configure as you would with Apache2::AuthCookieDBI, but leave out
 #   the PerlAuthzHandler directive and add the following when using "require group":

 PerlModule Apache2_4::AuthCookieDBI
 PerlAddAuthzProvider group Apache2_4::AuthCookieDBI->group

 <Location /www/domain.com/authcookiedbi/admin>
   require group admin
 </Location>

=head1 DESCRIPTION

This module is for F<mod_perl> version 2 and Apache version 2.4.x.  If you
are running Apache 2.0.0-2.2.x, refer to L<Apache2::AuthCookieDBI>.

B<Apache2_4::AuthCookieDBI> provides an Apache 2.4.x-compatible authorization
provider for handling "group" requirements.

Make sure your F<mod_perl> is at least 2.0.9, with StackedHandlers,
MethodHandlers, Authen, and Authz compiled in.

=head1 HISTORY

The implementation herein is based on L<Apache2::AuthCookieDBI>'s C<group>
method with heavy inspiration from the sample C<authz_handler> in
L<Apache2_4::AuthCookie> by Michael Schout. Huge thanks to Michael Schout for
his documentation on the changes to authorization under Apache 2.4.x.

=head1 COPYRIGHT

 Copyright (C) 2002 SF Interactive
 Copyright (C) 2003-2004 Jacob Davies
 Copyright (C) 2004-2019 Matisse Enzer

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
    Chad Columbus
    Edward J Sabol
    Jay Strauss
    Joe Ingersoll
    Keith Lawson
    Lance P Cleveland
    Matisse Enzer
    Nick Phillips
    William McKee
      
=head1 MAINTAINER

Matisse Enzer

        <matisse@cpan.org>
        
=head1 SEE ALSO

 Latest version: http://search.cpan.org/dist/Apache2-AuthCookieDBI

 Apache2::AuthCookie - http://search.cpan.org/dist/Apache2-AuthCookie
 Apache2::Session    - http://search.cpan.org/dist/Apache2-Session
 Apache::AuthDBI     - http://search.cpan.org/dist/Apache-DBI

=cut
