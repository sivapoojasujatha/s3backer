
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

#ifndef S3B_HTTP_IO_H
#define S3B_HTTP_IO_H

#include "http_gio.h"

/* S3 base URL / Host */
#define S3_DOMAIN                      "amazonaws.com"            /* S3 URL */

/* Authentication types */
#define AUTH_VERSION_AWS2              "aws2"
#define AUTH_VERSION_AWS4              "aws4"

/* S3-specific HTTP definitions */
#define S3B_FILE_SIZE_HEADER            "x-amz-meta-s3backer-filesize"
#define S3B_BLOCK_SIZE_HEADER           "x-amz-meta-s3backer-blocksize"
#define S3B_NAME_HASH_HEADER            "x-amz-meta-s3backer-namehash"
#define S3B_HMAC_HEADER                 "x-amz-meta-s3backer.hmac"
#define S3B_ACL_HEADER                  "x-amz-acl"
#define S3B_CONTENT_SHA256_HEADER       "x-amz-content-sha256"
#define S3B_STORAGE_CLASS_HEADER        "x-amz-storage-class"

/* AWS 4 `Date' and `x-amz-date' header formats */
#define AWS_DATE_HEADER                 "x-amz-date"
#define AWS_DATE_BUF_FMT                "%Y%m%dT%H%M%SZ"

/* AWS signature */
#define S3B_SIGNATURE_ALGORITHM         "AWS4-HMAC-SHA256"
#define S3B_ACCESS_KEY_PREFIX           "AWS4"
#define S3B_SERVICE_NAME                "s3"
#define S3B_SIGNATURE_TERMINATOR        "aws4_request"
#define S3B_SECURITY_TOKEN_HEADER       "x-amz-security-token"

/* EC2 IAM info URL */
#define S3B_EC2_IAM_META_DATA_URLBASE   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
#define S3B_EC2_IAM_META_DATA_ACCESSID  "AccessKeyId"
#define S3B_EC2_IAM_META_DATA_ACCESSKEY "SecretAccessKey"
#define S3B_EC2_IAM_META_DATA_TOKEN     "Token"

/* EC2 IAM thread */
int update_iam_credentials(struct http_io_private *priv);

/* Authentication functions */
int http_io_add_auth2(struct http_io_private *priv, struct http_io *io, time_t now, const void *payload, size_t plen);
int http_io_add_auth4(struct http_io_private *priv, struct http_io *io, time_t now, const void *payload, size_t plen);

/* S3 specific functions */
void set_http_io_s3b_params(struct http_io_conf *config);
void http_io_s3_destroy(struct http_io_private *const priv);
int http_io_s3b_bucket_attributes(struct cloudbacker_store *cb, void *arg);


#endif
