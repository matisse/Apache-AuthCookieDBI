# $Id: schema.sql,v 1.2 2010/11/27 19:15:37 matisse Exp $
#
# Schema for creating the database tables for an authentication system.

CREATE TABLE users (
	user     CHAR(16) PRIMARY KEY,
	password CHAR(24),
        active   BOOLEAN
);

CREATE TABLE groups (
	group CHAR(16),
	user CHAR(16)
);

