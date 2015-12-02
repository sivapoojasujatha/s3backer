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

#include <inttypes.h>

#define BLK_DEV_CAN_BE_USED         1
#define BLK_DEV_CANNOT_BE_USED      0

/* local store layer config structure */
struct localStore_io_conf {
    u_int               blocksize;
    uint64_t            size;
    char                *prefix; 
    char                *blk_dev_path;
    int                 readOnly;
    log_func_t          *log;
    int                 block_device_status;
};

/* Statistics structure for localStore_io */
struct local_io_stats {

     /* Block stats */
    u_int               local_normal_blocks_read;
    u_int               local_normal_blocks_written;
    u_int               local_zero_blocks_read;
    u_int               local_zero_blocks_written;

};

/* Internal state */
struct local_io_private {

    struct localStore_io_conf      *local_conf;                    /* local_io_store configuration structure */
    struct local_io_stats          stats;                          /* local_io_store statistics */    
    struct cloudbacker_store       *inner;
    struct blk_dev_t               *handle;                        /* block device handle */  
    u_int                          *bitmap;                        /* memory bit map updated during local store IO operations */
    pthread_mutex_t                mutex;
};


/* localStore_io.c */
extern struct cloudbacker_store *local_io_create(struct localStore_io_conf *config, struct cloudbacker_store *inner);
extern void local_io_get_stats(struct cloudbacker_store *cb, struct local_io_stats *stats);

