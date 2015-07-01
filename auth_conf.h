
/*
 * s3backer - FUSE-based single file backing store via Amazon S3
 * 
 * Copyright 2008-2011 Archie L. Cobbs <archie@dellroad.org>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef AUTH_CONF_H
#define AUTH_CONF_H

/* S3-specific configuration info */

struct auth_conf {
    union {
	struct {
	    char                *accessId;
	    char                *accessKey;
	    char                *iam_token;
	    const char          *accessType;
	    const char          *ec2iam_role;
	    const char          *authVersion;
	} s3;
	struct {
   	    char		*clientId; 
	    char		*p12_keyfile_path;
	    char		*auth_token;
	    const char          *accessType;
	} gs;
    } u;
};

#endif
