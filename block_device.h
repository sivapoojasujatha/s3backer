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

#include "localStore_io.h"

#define BITS_IN_CHAR                    8
#define ALIGNMENT	                4096


/* block device specific structures. */
struct blk_dev_meta;
struct blk_dev_t; 

/* block device opaque handle */
typedef struct blk_dev_t* blk_dev_handle_t;

extern blk_dev_handle_t blk_dev_open(struct local_io_private *priv, char *path, int readOnly, size_t blockSize, size_t size, char *prefix, log_func_t *log );

extern int blk_dev_close(struct local_io_private *priv);

extern size_t blk_dev_write(struct local_io_private *priv, const void *buf, off_t byte_offset, size_t nbytes);

extern size_t blk_dev_read(struct local_io_private *priv, char *buf, off_t byte_offset, size_t nbytes);

extern int blk_dev_flush(struct local_io_private *priv);
