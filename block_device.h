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
/*
 * packed data structure at the beginning of the block 0 on the block device
 * magic marker used to decide if the rest of the structure is initialized;
 * the version info is used to make sure the rest of the structure layout is known;
 * the rest of the info is to verify that the block device is the right one, and to
 * get the info needed to access the right offsets
 */
struct blk_dev_meta {
    union {
        struct {
	    char region[ALIGNMENT];
	} span;
	struct {
	    u_int         magic;                                      /* must be first in this specific order */
	    u_int         major_version, minor_version;               /* device major and minor versions */
	    size_t        bd_size;                                    /* device size */
	    size_t        bd_blocksize;                               /* block device physical block size */
            off_t         data_start_byteoffset;                      /* offset in bytes from where data blocks are written/read from device */
            int           app_prefix_len;                             /* length of the prefix string */
            char          app_prefix[128];                            /* string, --prefix="xyz" */
	
            /* bit map related stuff */
            off_t         bitmap_start_byteoffset;                    /* byte offset where bitmap is stored */
            size_t        bitmap_size;                                /* size of bitmap = no. of bytes in block device starting at bitmap_start_offset */
			
            /* block alignment stuff */
            size_t        alignment;                                  /* to align block device IO operations */
        } data;
    };
} __attribute__ ((packed));                                           /* byte packed */


/* 
 * block device opaque handle 
 */
typedef struct {
    struct blk_dev_meta    meta;                                      /* block device meta data */
    u_int                  *local_bitmap;                             /* memory bit map updated during IO operations */ 
    int                    fd;
    log_func_t             *log;
    size_t                 cb_blocksize;    
    size_t                 cb_size;
    char                   *prefix;
    char                   *blk_dev_path;
} blk_dev_t; 

typedef blk_dev_t* blk_dev_handle_t;

extern blk_dev_handle_t blk_dev_open(char *path, int readOnly, size_t blockSize, size_t size, char *prefix, log_func_t *log );

extern int blk_dev_close(blk_dev_handle_t handle);

extern size_t blk_dev_write(const void *buf, blk_dev_handle_t handle, off_t byte_offset, size_t nbytes);

extern size_t blk_dev_read(char *buf, blk_dev_handle_t handle, off_t byte_offset, size_t nbytes);

extern int blk_dev_flush(blk_dev_handle_t handle);
