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

#define METADATA_BLOCK_SIZE             512
#define METADATA_BLOCK_OFFSET           0

//void log_func_t(int level, const char *fmt, ...) __attribute__ ((__format__ (__printf__, 2, 3)));
//log_func_t *log;


/*
 * packed data structure at the beginning of the block 0 on the block device
 * magic marker used to decide if the rest of the structure is initialized;
 * the version info is used to make sure the rest of the structure layout is known;
 * the rest of the info is to verify that the block device is the right one, and to
 * get the info needed to access the right offsets
 */
struct blk_dev_meta {
    u_int         magic;                                      /* must be first in this specific order */
    u_int         major_version, minor_version;               /* device major and minor versions */
    size_t        size;                                       /* device size */
    size_t        blocksize;                                  /* physical block size */
    off_t         data_start_block_offset;                    /* offset in bytes from where data blocks are written/read from device */
    int           app_prefix_len;                             /* length of the prefix string */
    char          app_prefix[128];                            /* string, --prefix="xyz" */

    /* bit map related stuff */
    off_t         bitmap_start_offset;                        /* offset where bitmap is stored */
    off_t         bitmap_size;                                /* size of bitmap = no. of bytes in block device starting at bitmap_start_offset */

    /* block alignment stuff */
    size_t        block_alignment;                            /* to align block device IO operations */
    size_t        length;                                     /* to use for memalign calls */
    off_t         data_block_offset;                          /* offset should always be block aligned */

} __attribute__ ((packed));                                   /* byte packed */



typedef struct {
    int              fd;                                      /* the file descriptor for the underlying device */
    u_int            *local_bitmap;                           /* memory bit map updated during IO operations */ 
    struct           blk_dev_meta metadata;
} blk_dev_t;

typedef blk_dev_t * blk_dev_handle_t;

extern blk_dev_handle_t blk_dev_open(char *path, int flags);

extern int blk_dev_close(blk_dev_handle_t handle);

extern size_t blk_dev_write(const void *buf, blk_dev_handle_t handle, off_t byte_offset, size_t nbytes);

extern size_t blk_dev_read(char *buf, blk_dev_handle_t handle, off_t byte_offset, size_t nbytes);

