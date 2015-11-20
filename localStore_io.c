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

#include "cloudbacker.h"
#include "block_device.h"


/* Internal state */
struct local_io_private {

    struct localStore_io_conf      *local_conf;
    struct local_io_stats          stats;
    struct cloudbacker_store       *inner;
    blk_dev_handle_t               handle;
    pthread_mutex_t                mutex;
};


/* utility functions */
static int local_io_is_zero_block(const void *data, u_int block_size);

/* cloudbacker_store functions */
static int local_io_meta_data(struct cloudbacker_store *cb);
static int local_io_set_mounted(struct cloudbacker_store *cb, int *old_valuep, int new_value);
static int local_io_write_block(struct cloudbacker_store *cb, cb_block_t block_num, const void *src,
                                u_char *md5, check_cancel_t *check_cancel, void *arg);
static int local_io_read_block(struct cloudbacker_store *const cb, cb_block_t block_num, void *dest,
                               u_char *actual_md5, const u_char *expect_md5, int strict);
static void local_io_destroy(struct cloudbacker_store *cb);
static int local_io_flush(struct cloudbacker_store *const cb);

/* other functions */
static int local_io_write(struct local_io_private *const priv, off_t off, size_t len, const void *src);
static int local_io_read(struct local_io_private *const priv, off_t off, size_t len, void *dest);

/*
 * Constructor
 * On error, returns NULL and sets `errno'.
 */
struct cloudbacker_store *
local_io_create(struct localStore_io_conf *config, struct cloudbacker_store *inner, int readOnly)
{
    struct cloudbacker_store *cb;
    struct local_io_private *priv;
    int r;

    /* Initialize cloudbacker_store structure */
    if ((cb = calloc(1, sizeof(*cb))) == NULL) {
        r = errno;
        (*config->log)(LOG_ERR, "calloc(): %s", strerror(r));
        goto fail0;
    }

    cb->meta_data = local_io_meta_data;
    cb->set_mounted = local_io_set_mounted;
    cb->write_block = local_io_write_block;
    cb->read_block = local_io_read_block;
    cb->destroy = local_io_destroy;
    cb->flush = local_io_flush;

    /* Initialize local_io_private structure */
    if ((priv = calloc(1, sizeof(*priv))) == NULL) {
        r = errno;
        (*config->log)(LOG_ERR, "calloc(): %s", strerror(r));
        goto fail1;
    }
    priv->local_conf = config;
    priv->inner = inner;

    if ((r = pthread_mutex_init(&priv->mutex, NULL)) != 0){
        goto fail2;
    }

    cb->data = priv;
  
    /* if read fails, it means the block device is not initialized, write meta data and start using it. */
    pthread_mutex_lock(&priv->mutex);
    priv->handle = blk_dev_open(config->blk_dev_path, readOnly, config->block_size, config->size, config->prefix, config->log );
    if( priv->handle == NULL){
        pthread_mutex_unlock(&priv->mutex); 
        goto fail2;
    }
    pthread_mutex_unlock(&priv->mutex);
    return cb;

fail2:
    free(priv); 
fail1:
    free(cb);
fail0:
    (*config->log)(LOG_ERR, "local_io creation failed: %s", strerror(r));
    errno = r;
    return NULL;

}

static int
local_io_flush(struct cloudbacker_store *const cb)
{
	int rc;
    struct local_io_private *const priv = cb->data;

	if ((rc = blk_dev_flush(priv->handle)))
		return rc;

    return (*priv->inner->flush)(cb);
}

static void 
local_io_destroy(struct cloudbacker_store *cb)
{
    struct local_io_private *const priv = cb->data;

    pthread_mutex_lock(&priv->mutex);

    blk_dev_close(priv->handle);

    local_io_flush(cb);
    pthread_mutex_unlock(&priv->mutex);
    
    /* Destroy inner store */
    (*priv->inner->destroy)(priv->inner);

    /* Free structures */
    pthread_mutex_destroy(&priv->mutex);
    free(priv);
    free(cb);
}

static int
local_io_meta_data(struct cloudbacker_store *cb)
{
    struct local_io_private *priv = cb->data;
   
    return (*priv->inner->meta_data)(priv->inner); 
}

static int
local_io_set_mounted(struct cloudbacker_store *cb, int *old_valuep, int new_value)
{
    struct local_io_private *const priv = cb->data;

    return (*priv->inner->set_mounted)(priv->inner, old_valuep, new_value);
}

static int
local_io_write_block(struct cloudbacker_store *cb, cb_block_t block_num, const void *src, u_char *md5, check_cancel_t *check_cancel, void *arg)
{
    struct local_io_private *const priv = cb->data;
    struct localStore_io_conf *const config = priv->local_conf;
    blk_dev_handle_t handle = priv->handle; 
    int num_blocks =  handle->cb_size / handle->cb_blocksize;

    /* Sanity check */
    if (config->block_size == 0 || block_num >= num_blocks)
        return EINVAL;

    /* Will write zero blocks locally for nowm but log this */
    if (src != NULL) {
        if (local_io_is_zero_block(src, handle->cb_blocksize))
            src = NULL;
    }

    /* Logging */
    (*config->log)(LOG_DEBUG, "local_io: write block %0*jx %s",
                               CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num, src == NULL ? " (zero block)" : "(nonzero block)");


    pthread_mutex_lock(&priv->mutex);
    /* compute the offset as per the mounted file system block size and block device block size */
    off_t offset = 0;
    int r = 0;

    /* offset is in bytes
     * assume data_start_offset = 512 byte offset and cb_blocksize=4096bytes
     * b0 will be written at 512+(4096*0) = 512 byte offset
     * b1 will be written at 512+(4096*1) = 4608 byte offset and so on
     */
    offset = handle->meta.data.data_start_byteoffset + (priv->handle->cb_blocksize * block_num); 

    if (priv->handle->local_bitmap != NULL) {
        const int bits_per_word = sizeof(*priv->handle->local_bitmap) * BITS_IN_CHAR;
        const int word = block_num / bits_per_word;
        const int bit = 1 << (block_num % bits_per_word);

        if (src == NULL) {
            priv->stats.local_zero_blocks_written++;
        }
        else{
            priv->stats.local_normal_blocks_written++;
        }
		r = local_io_write(priv, offset, priv->handle->cb_blocksize, src);
        priv->handle->local_bitmap[word] |= bit;
        //(*config->log)(LOG_DEBUG, "writing block: %0*jx, %s", CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num, ((priv->handle->local_bitmap[word] & bit) != 0) ? "bit set":"bitnotset");

        pthread_mutex_unlock(&priv->mutex);
        return r;
    } else {
		/* Can't function without local bitmap - the read will not work */
		r = EIO;
	}

    pthread_mutex_unlock(&priv->mutex);
    return r;

}

static int
local_io_write(struct local_io_private *const priv, off_t off, size_t len, const void *src)
{
    struct localStore_io_conf *const config = priv->local_conf;

    size_t sofar;
    ssize_t r;

    for (sofar = 0; sofar < len; sofar += r) {
        const off_t posn = off + sofar;

        if ((r = blk_dev_write(((const char *)src + sofar), priv->handle, off + sofar, len - sofar)) <= 0) {
            (*config->log)(LOG_ERR, "error writing block device file at offset %ju: %s", (uintmax_t)posn, strerror(r));
            goto fail;
        }
    }
    if(sofar != len){
        (*config->log)(LOG_ERR, "error writing block device file, file is truncated");
        goto fail;
    }
    
    return 0;

fail:
    return EIO;
}

static int
local_io_read_block(struct cloudbacker_store *const cb, cb_block_t block_num, void *dest, u_char *actual_md5, const u_char *expect_md5, int strict)
{
    struct local_io_private *const priv = cb->data;
    struct localStore_io_conf *const config = priv->local_conf;
    blk_dev_handle_t handle = priv->handle;
    int rc = 0;

    off_t offset = 0;
    /* offset is in bytes
     * assume data_start_offset = 512 byte offset and cb_blocksize=4096bytes
     * b0 will be read at 512+(4096*0) = 512 byte offset
     * b1 will be read at 512+(4096*1) = 4608 byte offset and so on
     */
    offset = handle->meta.data.data_start_byteoffset + (priv->handle->cb_blocksize * block_num);

    /* Sanity check */
    if ((config->block_size == 0) || (offset + handle->cb_blocksize > handle->cb_size))
        return EINVAL;

    pthread_mutex_lock(&priv->mutex);
 
    /* Logging */
    (*config->log)(LOG_DEBUG, "reading block: %0*jx", CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num);

    if (priv->handle->local_bitmap != NULL) {
        const int bits_per_word = (sizeof(*priv->handle->local_bitmap) * BITS_IN_CHAR);
        const int word = block_num / bits_per_word;
        const int bit = 1 << (block_num % bits_per_word);

        /* if bit is set, then block exists in local store, else read from cloud store or test store(if --test flag is used) */
        if ((priv->handle->local_bitmap[word] & bit) != 0) {

            priv->stats.local_normal_blocks_read++;
            pthread_mutex_unlock(&priv->mutex);     
            return local_io_read(priv, offset, handle->cb_blocksize, dest);
        }
        else {
            pthread_mutex_unlock(&priv->mutex);
            return (*priv->inner->read_block)(priv->inner, block_num, dest, actual_md5, expect_md5, strict);
        }
    } else {
        rc = EIO;
    }
    pthread_mutex_unlock(&priv->mutex);
    return rc;
}

/*
 * Read a block.
 */
static int
local_io_read(struct local_io_private *const priv, off_t off, size_t len, void *dest)
{
    struct localStore_io_conf *const config = priv->local_conf;

    pthread_mutex_lock(&priv->mutex);

    size_t sofar;
    size_t r;

    /* perform read */
    for (sofar = 0; sofar < len; sofar += r) {
        const off_t posn = off + sofar;

        if ((r = blk_dev_read(((char *)dest + sofar), priv->handle, off + sofar, len - sofar)) <= 0) {
            (*config->log)(LOG_ERR, "error reading block device file at offset %ju: %s",
              (uintmax_t)posn, strerror(r));
            goto fail;
        }
    }

    if(sofar != len){
        (*config->log)(LOG_ERR, "error reading block device file, file is truncated");
        memset(dest,0,len);
        goto fail;
    }

    /* Check is block read is zero block */
    if(local_io_is_zero_block(dest, len)){
        priv->stats.local_zero_blocks_read++;
    }

    pthread_mutex_unlock(&priv->mutex);
    return 0;

fail:
    pthread_mutex_unlock(&priv->mutex);
    return EIO;
}

void
local_io_get_stats(struct cloudbacker_store *cb, struct local_io_stats *stats)
{
    struct local_io_private *const priv = cb->data;

    pthread_mutex_lock(&priv->mutex);
    memcpy(stats, &priv->stats, sizeof(*stats));
    pthread_mutex_unlock(&priv->mutex);
}

int
local_io_is_zero_block(const void *data, u_int block_size)
{
    static const u_long zero;
    const u_int *ptr;
    int i;

    if (block_size <= sizeof(zero))
        return memcmp(data, &zero, block_size) == 0;
    ptr = (const u_int *)data;
    for (i = 0; i < block_size / sizeof(*ptr); i++) {
        if (*ptr++ != 0)
            return 0;
    }
    return 1;
}
