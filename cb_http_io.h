
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

#ifndef CB_HTTP_IO_H
#define CB_HTTP_IO_H

#include "http_gio.h"

/*
======================================================================================================
************************************ Cloudbacker Error Codes *****************************************
======================================================================================================
*/

#define ERR_SUCCESS				0
#define ERR_ENCRYPTION_FAILURE			1
#define ERR_OPENSSL_LOCK_FAILURE		2

/*
======================================================================================================
************************ Cloudbacker - Amazon S3 Storage specific parameters *************************
======================================================================================================
*/

#define AUTH_VERSION_AWS2   "aws2"
#define AUTH_VERSION_AWS4   "aws4"

#define S3_DOMAIN                       "amazonaws.com"

/* S3-specific HTTP definitions */
#define S3B_FILE_SIZE_HEADER            "x-amz-meta-s3backer-filesize"
#define S3B_BLOCK_SIZE_HEADER           "x-amz-meta-s3backer-blocksize"
#define S3B_NAME_HASH_HEADER            "x-amz-meta-s3backer-namehash"
#define S3B_HMAC_HEADER                 "x-amz-meta-s3backer.hmac"
#define S3B_ACL_HEADER                  "x-amz-acl"
#define S3B_CONTENT_SHA256_HEADER       "x-amz-content-sha256"
#define S3B_STORAGE_CLASS_HEADER        "x-amz-storage-class"

/* `x-amz-date' header formats */
#define AWS_DATE_HEADER                 "x-amz-date"
#define AWS_DATE_BUF_FMT            	"%Y%m%dT%H%M%SZ"

/* AWS signature */
#define S3B_SIGNATURE_ALGORITHM         "AWS4-HMAC-SHA256"
#define S3B_ACCESS_KEY_PREFIX           "AWS4"
#define S3B_SERVICE_NAME                "s3"
#define S3B_SIGNATURE_TERMINATOR        "aws4_request"
#define S3B_SECURITY_TOKEN_HEADER       "x-amz-security-token"

/*
========================================================================================================
****************************************  EC2 IAM info URL  ********************************************
========================================================================================================
*/

#define S3B_EC2_IAM_META_DATA_URLBASE   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
#define S3B_EC2_IAM_META_DATA_ACCESSID  "AccessKeyId"
#define S3B_EC2_IAM_META_DATA_ACCESSKEY "SecretAccessKey"
#define S3B_EC2_IAM_META_DATA_TOKEN     "Token"

/*
========================================================================================================
*********************** Cloudbacker - Google Cloud Storage specific parameters *************************
========================================================================================================
*/

/* JWT constants */

//JWT header format    {"alg":"RS256","typ":"JWT"}

#define JWT_HEADER_ALG                  "alg"
#define JWT_HEADER_RS256                "RS256"
#define JWT_HEADER_TYPE                 "typ"
#define JWT_HEADER_JWT                  "JWT"
#define JWT_HEADER_BUF_LEN               28		// len({"alg":"RS256","typ":"JWT"})+1 for '\0'

#define JWT_CLAIMSET_ISS                "iss"
#define JWT_CLAIMSET_SCOPE              "scope"
#define JWT_CLAIMSET_SCOPE_VALUE        "https://www.googleapis.com/auth/devstorage.read_write"
#define JWT_CLAIMSET_AUD                "aud"
#define JWT_CLAIMSET_AUD_VALUE          "https://www.googleapis.com/oauth2/v3/token"
#define JWT_CLAIMSET_EXP                "exp"
#define JWT_CLAIMSET_IAT                "iat"

#define GS_DOMAIN                       "storage.googleapis.com"
#define AUTH_VERSION_OAUTH2   		"oauth2"

#define JWT_AUTH_DEFAULT_PASSWORD       "notasecret"
#define GCS_OAUTH2_ACCESS_TOKEN         "access_token"

/* GS-specific HTTP definitions */
#define GSB_FILE_SIZE_HEADER            "x-goog-meta-gsbacker-filesize"
#define GSB_BLOCK_SIZE_HEADER           "x-goog-meta-gsbacker-blocksize"
#define GSB_NAME_HASH_HEADER            "x-goog-meta-gsbacker-namehash"
#define GSB_HMAC_HEADER                 "x-goog-meta-gsbacker.hmac"
#define GSB_ACL_HEADER                  "x-goog-acl"
#define GSB_CONTENT_SHA256_HEADER       "x-goog-content-sha256"
#define GSB_STORAGE_CLASS_HEADER        "x-goog-storage-class"


/*
========================================================================================================
*************************************  Function prototypes  ********************************************
========================================================================================================
*/

struct cloudbacker_store *cb_http_io_create(struct http_io_conf *config);

#endif
