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
#include "block_part.h"

/* cloudbacker_store functions */
static int local_io_init(struct cloudbacker_store *cb, int mounted);
static int local_io_meta_data(struct cloudbacker_store *cb);
static int local_io_set_mounted(struct cloudbacker_store *cb, int *old_valuep, int new_value);
static int local_io_write_block(struct cloudbacker_store *cb, cb_block_t block_num, const void *src,
                                u_char *md5, check_cancel_t *check_cancel, void *arg);
static int local_io_read_block(struct cloudbacker_store *const cb, cb_block_t block_num, void *dest,
                               u_char *actual_md5, const u_char *expect_md5, int strict);
static int local_io_read_block_part(struct cloudbacker_store *cb, cb_block_t block_num, u_int off,
                                    u_int len, void *dest);
static int local_io_write_block_part(struct cloudbacker_store *cb, cb_block_t block_num, u_int off, 
                                     u_int len, const void *src);
static void local_io_destroy(struct cloudbacker_store *cb);
static int local_io_flush(struct cloudbacker_store *const cb);

static int local_io_is_zero_block(const void *data, u_int block_size);

/*
 * Constructor
 * On error, returns NULL and sets `errno'.
 */
struct cloudbacker_store *
local_io_create(struct localStore_io_conf *config, struct cloudbacker_store *inner)
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
    cb->write_block_part = local_io_write_block_part;
    cb->read_block_part = local_io_read_block_part;
    cb->destroy = local_io_destroy;
    cb->flush = local_io_flush;
    cb->init = local_io_init;
	
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
   
    /* Done */
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
local_io_init(struct cloudbacker_store *cb, int mounted)
{
    struct local_io_private *const priv = cb->data;
    struct localStore_io_conf *const config = priv->local_conf;

    /* if already created */
    if(priv->handle != NULL)
       return -1;
    pthread_mutex_lock(&priv->mutex);
    config->block_device_status = BLK_DEV_CANNOT_BE_USED;
    priv->handle = blk_dev_open(priv, config->blk_dev_path, config->readOnly, config->blocksize, config->size, config->prefix, config->log );
    if( priv->handle == NULL){
        pthread_mutex_unlock(&priv->mutex);
        return EINVAL;
    }
    config->block_device_status = BLK_DEV_CAN_BE_USED;
    pthread_mutex_unlock(&priv->mutex);
    return 0;
}

static int
local_io_flush(struct cloudbacker_store *const cb)
{
    int rc;
    struct local_io_private *const priv = cb->data;

    /* Grab lock and sanity check */
    pthread_mutex_lock(&priv->mutex);

    /* flush data */
    rc = blk_dev_flush(priv);

    /* Release lock */
    pthread_mutex_unlock(&priv->mutex);

    if (rc != 0)
        return rc;

    return (*priv->inner->flush)(cb);
}

static void 
local_io_destroy(struct cloudbacker_store *cb)
{
    struct local_io_private *const priv = cb->data;

    pthread_mutex_lock(&priv->mutex);

    blk_dev_close(priv);

   if(priv->bitmap != NULL)
       free(priv->bitmap);
   
    pthread_mutex_unlock(&priv->mutex);
    
    /* Destroy inner store */
    if(priv->inner != NULL)
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

/*
 * write the block
 */
static int
local_io_write_block(struct cloudbacker_store *cb, cb_block_t block_num, const void *src, u_char *md5, check_cancel_t *check_cancel, void *arg)
{
    struct local_io_private *const priv = cb->data;
    struct localStore_io_conf *const config = priv->local_conf;    
	
     cb_block_t num_blocks = config->size / config->blocksize;

    /* Sanity check */
    if ((config->blocksize == 0) || (block_num >= num_blocks))
        return EINVAL;
 
    /* get lock */
    pthread_mutex_lock(&priv->mutex);

    /* Will write zero blocks locally for now but log this */
     if (src != NULL) {
         if (local_io_is_zero_block(src, config->blocksize))
            src = NULL;
     }

    off_t offset = 0;
    int r = 0;
    /* compute the offset as per the mounted file system block size */
    offset = (config->blocksize * block_num);

    /* Logging */
    (*config->log)(LOG_DEBUG, "localStore :: write block : %0*jx %s",
                               CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num, (src == NULL) ? " (zero block)" : "(nonzero block)");


    if (priv->bitmap != NULL) {
        const int bits_per_word = sizeof(*priv->bitmap) * BITS_IN_CHAR;
        const int word = block_num / bits_per_word;
        const int bit = 1 << (block_num % bits_per_word);

        if(src == NULL){ 
            priv->stats.local_zero_blocks_written++;
        }
        else{
            priv->stats.local_normal_blocks_written++;
        }
        if((r = blk_dev_write(priv, src, offset, config->blocksize)) == config->blocksize)
           r = 0; //write success
        else 
           r = EIO; 
       
        priv->bitmap[word] |= bit;

    } else {
        /* Can't function without local bitmap - the write will not work */
        r = EIO;
    }
    
    pthread_mutex_unlock(&priv->mutex);
    return r;
}

/*
 * read the block
 */
static int
local_io_read_block(struct cloudbacker_store *const cb, cb_block_t block_num, void *dest, u_char *actual_md5, const u_char *expect_md5, int strict)
{
    struct local_io_private *const priv = cb->data;
    struct localStore_io_conf *const config = priv->local_conf;
	
    cb_block_t num_blocks = config->size / config->blocksize;

    /* Sanity check */
    if ((config->blocksize == 0) || (block_num >= num_blocks))
        return EINVAL;

    /* get lock */
    pthread_mutex_lock(&priv->mutex);

    off_t offset = 0;
    int r = 0;

    /* compute the offset as per the mounted file system block size */
    offset = (config->blocksize * block_num);
 
    /* Logging */
    (*config->log)(LOG_DEBUG, "localStore :: read block: %0*jx", CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num);

     if (priv->bitmap != NULL) {
        const int bits_per_word = (sizeof(*priv->bitmap) * BITS_IN_CHAR);
        const int word = block_num / bits_per_word;
        const int bit = 1 << (block_num % bits_per_word);

        /* if bit is set, then block exists in local store, else read from cloud store or test store(if --test flag is used) */
        if ((priv->bitmap[word] & bit) != 0) {

            if((r = blk_dev_read(priv, dest, offset, config->blocksize)) == config->blocksize)
               r = 0;     //read success
            else
               r = EIO;

            /* Check if block read is zero block */
            if(local_io_is_zero_block(dest,config->blocksize)){
                priv->stats.local_zero_blocks_read++;
            }
            else {
                priv->stats.local_normal_blocks_read++;
            }
        }
        else {
             pthread_mutex_unlock(&priv->mutex);
             return (*priv->inner->read_block)(priv->inner, block_num, dest, actual_md5, expect_md5, strict);
        }
    } else {
        r = EIO;
    }
    
    pthread_mutex_unlock(&priv->mutex);	
    return r;
}

static int
local_io_read_block_part(struct cloudbacker_store *cb, cb_block_t block_num, u_int off, u_int len, void *dest)
{
    struct local_io_private *const priv = cb->data;
    struct localStore_io_conf *const config = priv->local_conf;

    return block_part_read_block_part(cb, block_num, config->blocksize, off, len, dest);
}

static int
local_io_write_block_part(struct cloudbacker_store *cb, cb_block_t block_num, u_int off, u_int len, const void *src)
{
    struct local_io_private *const priv = cb->data;
    struct localStore_io_conf *const config = priv->local_conf;

    return block_part_write_block_part(cb, block_num, config->blocksize, off, len, src);
}

/* 
 * get localStore IO operation statistics 
 */
void
local_io_get_stats(struct cloudbacker_store *cb, struct local_io_stats *stats)
{
    struct local_io_private *const priv = cb->data;

    pthread_mutex_lock(&priv->mutex);
    memcpy(stats, &priv->stats, sizeof(*stats));
    pthread_mutex_unlock(&priv->mutex);
}

/*
 * checks if all bytes in the buffer are zeroes
 */
static int
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

