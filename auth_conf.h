
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

/* cloudbacker authentication specific configuration info */

struct auth_conf {

    union {

        /* S3 authentication specific configuration info */
        struct {
	    char                *accessId;             /* Amazon s3 access Id */
	    char                *accessKey;            /* Amazon s3 secret or access key */
	    char                *iam_token;            /* EC2 IAM token */
	    const char          *accessType;           /* accesstype for the Amazon s3 bucket */
	    const char          *ec2iam_role;          /* EC2 IAM role */
	    const char          *authVersion;          /* authentication version, AWS4 or AWS2 */
	} s3;
       
        /* Google storage authentication specific configuration info */
	struct {
	    char                *clientId;              /* google cloud storage clienId(xyz@developer.gserviceaccount.com) */
            char                *secret_keyfile;        /* google cloud storage downloaded secret key file(either p12 or json format) */
            char                *auth_token;            /* authorization token to get access to resources/APIs */
            const char          *accessType;            /* accesstype for the google cloud storage bucket */
            const char          *authVersion;           /* authentication version, oAUTH 2.0 or AWS2 */

	} gs;

    } u;       
};

#endif
