
/*
 * cloudbacker - FUSE-based single file backing store
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

/* structure holds all http parameters used in cloudbacker store http reqests as per storage type */
typedef struct http_io_parameters{

    char file_size_header[32];
    char block_size_header[32];
    char compression_level_header[64];
    char encrypted_header[32];
    char encryption_cipher_header[40];
    char serverside_encryption_header[32];
    u_int block_size_headerval;
    char HMAC_Header[32];
    char HMAC_Headerval[64];
    char name_hash_header[32];
    char acl_header[32];
    char acl_headerval[64];
    char content_sha256_header[24];
    char storage_class_header[24];
    char storage_class_headerval[32];
    char date_header[24];
    char date_buf_fmt[64];
    char signature_algorithm[32];
    char accessKey_prefix[16];
    char service_name[32];
    char signature_terminator[16];
    char security_token_header[32];
    char ec2_iam_meta_data_urlbase[96];
    char ec2_iam_meta_data_accessID[16];
    char ec2_iam_meta_data_accessKey[24];
    char ec2_iam_meta_data_token[8];
    char cb_domain[24];
}http_io_parameters;


#endif
