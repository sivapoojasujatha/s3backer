
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

/* s3b_http_io.c */
extern struct s3backer_store *http_io_create(struct http_io_conf *config);
extern void http_io_get_stats(struct s3backer_store *s3b, struct http_io_stats *stats);
extern int http_io_parse_block(struct http_io_conf *config, const char *name, s3b_block_t *block_num);

#endif
