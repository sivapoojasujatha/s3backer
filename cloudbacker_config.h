
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

#ifndef CB_CONFIG_H
#define CB_CONFIG_H

#include "http_gio.h"
#include "localStore_io.h"

/* Overal application configuration info */
struct cb_config {

    /* Various sub-module configurations */
    struct block_cache_conf     block_cache;
    struct fuse_ops_conf        fuse_ops;
    struct ec_protect_conf      ec_protect;
    struct http_io_conf         http_io;
    struct localStore_io_conf   localStore_io;
 
    /* Common/global stuff */
    const char                  *accessFile;
    const char                  *mount;
    char                        description[768];
    u_int                       block_size;
    uintmax_t                   file_size;
    off_t                       num_blocks;
    int                         debug;
    int                         erase;
    int                         reset;
    int                         quiet;
    int                         force;
    int                         test;
    int                         ssl;
    int                         no_auto_detect;
    int                         list_blocks;
    int                         list_blocks_async;
    struct fuse_args            fuse_args;
    log_func_t                  *log;

    /* These are only used during command line parsing */
    const char                  *file_size_str;
    const char                  *block_size_str;
    const char                  *password_file;
    const char                  *max_speed_str[2];
    int                         encrypt;
};

extern struct cb_config *cloudbacker_get_config(int argc, char **argv);
extern struct cloudbacker_store *cloudbacker_create_store(struct cb_config *config);

#endif
