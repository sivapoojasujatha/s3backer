
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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

/* Add some queue.h definitions missing on Linux */
#ifndef LIST_FIRST
#define LIST_FIRST(head)        ((head)->lh_first)
#endif
#ifndef LIST_NEXT
#define LIST_NEXT(item, field)  ((item)->field.le_next)
#endif
#ifndef TAILQ_FIRST
#define TAILQ_FIRST(head)       ((head)->tqh_first)
#endif
#ifndef TAILQ_NEXT
#define TAILQ_NEXT(item, field) ((item)->field.tqe_next)
#endif

#include <assert.h>
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <expat.h>
#include <fcntl.h>
#include <pthread.h>
#include <regex.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <zlib.h>
#include <fuse.h>

#ifndef FUSE_OPT_KEY_DISCARD
#define FUSE_OPT_KEY_DISCARD -4
#endif

/* In case we don't have glibc >= 2.18 */
#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE     0x01
#endif
#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE    0x02
#endif

/*
 * Integral type for holding a block number.
 */
typedef uint64_t    cb_block_t;

/*
 * How many hex digits we will use to print a block number.
 */
#define CB_BLOCK_NUM_DIGITS    ((int)(sizeof(cb_block_t) * 2))

/* Logging function type */
typedef void        log_func_t(int level, const char *fmt, ...) __attribute__ ((__format__ (__printf__, 2, 3)));

/* Block list callback function type */
typedef void        block_list_func_t(void *arg, cb_block_t block_num);

/* Block write cancel check function type */
typedef int         check_cancel_t(void *arg, cb_block_t block_num);

/* Backing store instance structure */
struct cloudbacker_store {

    /*
     * Get meta-data associated with the underlying store.
     *
     * The information we acquire is:
     *  o Block size
     *  o Total size
     *  o Name hashing (on/off)
     *
     * Returns:
     *
     *  0       Success
     *  ENOENT  Information not found
     *  Other   Other error
     */
    int         (*meta_data)(struct cloudbacker_store *cb);

    /*
     * Read and (optionally) set the mounted flag.
     *
     * Previous value is returned in *old_valuep (if not NULL).
     *
     * new_value can be:
     *  -1      Don't change it
     *   0      Clear it
     *   1      Set it
     *
     * Returns zero on success or a (positive) errno value on error.
     */
    int         (*set_mounted)(struct cloudbacker_store *cb, int *old_valuep, int new_value);

    /*
     * Read one block. Never-written-to blocks will return all zeroes.
     *
     * If not NULL, 'actual_md5' should be filled in with a value suitable for the 'expect_md5' parameter,
     * or all zeroes if unknown.
     *
     * If 'expect_md5' is not NULL:
     *  - expect_md5 should be the value returned from a previous call to read_block() or write_block().
     *  - If strict != 0, expect_md5 must be the value returned from the most recent call to write_block()
     *    and the data must match it or else an error is returned. Aside from this check, read normally.
     *  - If strict == 0:
     *    - If block's MD5 does not match expect_md5, expect_md5 is ignored and the block is read normally
     *    - If block's MD5 matches expect_md5, the implementation may either:
     *      - Ignore expect_md5 and read the block normally; OR
     *      - Return EEXIST; the block may or may not also be read normally into *dest
     *
     * Returns zero on success or a (positive) errno value on error.
     */
    int         (*read_block)(struct cloudbacker_store *cb, cb_block_t block_num, void *dest,
                  u_char *actual_md5, const u_char *expect_md5, int strict);

    /*
     * Read part of one block.
     *
     * Returns zero on success or a (positive) errno value on error.
     */
    int         (*read_block_part)(struct cloudbacker_store *cb, cb_block_t block_num, u_int off, u_int len, void *dest);

    /*
     * Write meta data block. This block will have zero data.
     * We are writing only user defined meta data like
     * filesystem size
     * block size
     * name Hashing for blocks
     * encryption cipher or algorithm
     * compression flag
     */
    int         (*set_meta_data)(struct cloudbacker_store *cb, int operation);

    /*
     * Initialize block device for IO operations
     * Only if http store or test store is mounted, local IO store should be initialized.
     * Helps in preventing concurrent access to the specified block device from multiple processes.
     */   
    int         (*init)(struct cloudbacker_store *cb, int mounted);
    /*
     * Write one block.
     *
     * Passing src == NULL is equivalent to passing a block containing all zeroes.
     *
     * If check_cancel != NULL, then it may be invoked periodically during the write. If so, and it ever
     * returns a non-zero value, then this function may choose to abort the write and return ECONNABORTED.
     *
     * Upon successful return, md5 (if not NULL) will get updated with a value suitable for the 'expect_md5'
     * parameter of read_block(); if the block is all zeroes, md5 will be zeroed.
     *
     * Returns zero on success or a (positive) errno value on error.
     */
    int         (*write_block)(struct cloudbacker_store *cb, cb_block_t block_num, const void *src, u_char *md5,
                  check_cancel_t *check_cancel, void *arg);

    /*
     * Write part of one block.
     *
     * Returns zero on success or a (positive) errno value on error.
     */
    int         (*write_block_part)(struct cloudbacker_store *cb, cb_block_t block_num, u_int off, u_int len, const void *src);

    /*
     * Identify all non-zero blocks.
     *
     * Returns zero on success or a (positive) errno value on error.
     */
    int         (*list_blocks)(struct cloudbacker_store *cb, block_list_func_t *callback, void *arg);
    /*
     * Get bucket attributes, currently implemented only to fetch storageClass attribute.
     *
     * Returns zero on success or a (positive) errno value on error.
     */
    int         (*bucket_attributes)(struct cloudbacker_store *cb, void *arg);

    /*
     * Sync any dirty data to the underlying data store.
     */
    int         (*flush)(struct cloudbacker_store *cb, int stop);

    /*
     * Destroy this instance.
     */
    void        (*destroy)(struct cloudbacker_store *cb);

    /*
     * Implementation private data
     */
    void        *data;
};

/* gitrev.c */
extern const char *const cloudbacker_version;

