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

#ifndef GSB_HTTP_IO_H
#define GSB_HTTP_IO_H

#include "http_gio.h"

/*
 * Cloudbacker - Google Cloud Storage specific parameters
 */

#define AUTH_VERSION_OAUTH2   		"oauth2"
#define GCS_OAUTH2_ACCESS_TOKEN         "access_token"

/* HTTP IO specific definitions */
#define GSB_FILE_SIZE_HEADER            "x-goog-meta-gsbacker-filesize"
#define GSB_BLOCK_SIZE_HEADER           "x-goog-meta-gsbacker-blocksize"
#define GSB_NAME_HASH_HEADER            "x-goog-meta-gsbacker-namehash"
#define GSB_HMAC_HEADER                 "x-goog-meta-gsbacker.hmac"
#define GSB_ACL_HEADER                  "x-goog-acl"
#define GSB_CONTENT_SHA256_HEADER       "x-goog-content-sha256"
#define GSB_STORAGE_CLASS_HEADER        "x-goog-storage-class"

/*
 * Function Prototypes
 */


#endif
