
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

#ifndef S3B_HTTP_IO_H
#define S3B_HTTP_IO_H

#include "http_gio.h"

/* Authentication types */
#define AUTH_VERSION_AWS2   "aws2"
#define AUTH_VERSION_AWS4   "aws4"

/* S3-specific HTTP definitions */
#define S3B_FILE_SIZE_HEADER            "x-amz-meta-s3backer-filesize"
#define S3B_BLOCK_SIZE_HEADER           "x-amz-meta-s3backer-blocksize"
#define S3B_NAME_HASH_HEADER            "x-amz-meta-s3backer-namehash"
#define S3B_HMAC_HEADER                 "x-amz-meta-cloudbacker.hmac"
#define S3B_ACL_HEADER                  "x-amz-acl"
#define S3B_CONTENT_SHA256_HEADER       "x-amz-content-sha256"
#define S3B_STORAGE_CLASS_HEADER        "x-amz-storage-class"

/* AWS 4 `Date' and `x-amz-date' header formats */
#define AWS_DATE_HEADER             "x-amz-date"
#define AWS_DATE_BUF_FMT            "%Y%m%dT%H%M%SZ"

/* AWS signature */
#define SIGNATURE_ALGORITHM         "AWS4-HMAC-SHA256"
#define ACCESS_KEY_PREFIX           "AWS4"
#define S3_SERVICE_NAME             "s3"
#define SIGNATURE_TERMINATOR        "aws4_request"
#define SECURITY_TOKEN_HEADER       "x-amz-security-token"

/* EC2 IAM info URL */
#define EC2_IAM_META_DATA_URLBASE   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
#define EC2_IAM_META_DATA_ACCESSID  "AccessKeyId"
#define EC2_IAM_META_DATA_ACCESSKEY "SecretAccessKey"
#define EC2_IAM_META_DATA_TOKEN     "Token"

/* http_gio.c 
extern struct cloudbacker_store *http_io_create(struct http_io_conf *config);
extern void http_io_get_stats(struct cloudbacker_store *cb, struct http_io_stats *stats);
extern int http_io_parse_block(struct http_io_conf *config, const char *name, cb_block_t *block_num);
*/

#endif
