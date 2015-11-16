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

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>

#define BITS_IN_CHAR                    8
#define MAX_PREFIX_LENGTH               128 
#define DEVICE_INITIALIZED              0
#define DEVICE_NOT_INITIALIZED          1
#define DEVICE_CANT_BE_USED             2

#define MAGIC_STRING                    0xC104DBAC
#define MAJOR_NUMBER                    1
#define MINOR_NUMBER                    0

/* Internal state */
struct local_io_private {

    struct localStore_io_conf      *local_conf;
    struct local_io_stats          stats;
    struct cloudbacker_store       *inner;
    blk_dev_handle_t               handle;
    int                            readOnly;
    pthread_mutex_t                mutex;
};


/* utility functions */
static int local_io_is_zero_block(const void *data, u_int block_size);
static int local_io_set_config(struct local_io_private *const priv);
static blk_dev_handle_t local_io_get_config(struct local_io_private *const priv);
static int local_io_validate_config(struct local_io_private *const priv);
static int read_bitmap(struct local_io_private *const priv);
static int write_bitmap(struct local_io_private *const priv);

/* cloudbacker_store functions */
static int local_io_meta_data(struct cloudbacker_store *cb);
static int local_io_set_mounted(struct cloudbacker_store *cb, int *old_valuep, int new_value);
static int local_io_write_block(struct cloudbacker_store *cb, cb_block_t block_num, const void *src, u_char *md5,
                                check_cancel_t *check_cancel, void *arg);
static int local_io_read_block(struct cloudbacker_store *const cb, cb_block_t block_num, void *dest, u_char *actual_md5,
                               const u_char *expect_md5, int strict);
static void local_io_destroy(struct cloudbacker_store *cb);
static int local_io_flush(struct cloudbacker_store *const cb);

/* other functions */
static int local_io_write(struct local_io_private *const priv, u_int block_num, u_int off, u_int len, const void *src);
static int local_io_read(struct local_io_private *const priv, cb_block_t block_num, u_int off, u_int len, void *dest);

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
    priv->readOnly = readOnly;

    if ((r = pthread_mutex_init(&priv->mutex, NULL)) != 0){
        goto fail2;
    }

    cb->data = priv;

   
    /* if read fails, it means the block device is not initialized, write meta data and start using it. */
    pthread_mutex_lock(&priv->mutex);
    priv->handle = local_io_get_config(priv);
    if(priv->handle != NULL){

        int ret = local_io_validate_config(priv);
        if(ret == DEVICE_INITIALIZED){

            size_t nwords;
            u_int *bitmap;

            int num_blocks = priv->handle->metadata.size / priv->handle->metadata.blocksize;

            nwords = (num_blocks + (sizeof(*bitmap) * BITS_IN_CHAR) - 1) / (sizeof(*bitmap) * BITS_IN_CHAR);
            if ((priv->handle->local_bitmap = calloc(nwords, sizeof(*bitmap))) == NULL)
                err(1, "calloc");

            /* metadata read from meta data region is valid, now read the bitmap from device into memory */
            ret = read_bitmap(priv);
            if(ret != 0){
                 r = errno;
                (*config->log)(LOG_DEBUG, "read_bitmap returned = %d", ret);
                goto fail3;
            }
        }
        else if(ret == DEVICE_NOT_INITIALIZED){

            /* initialize metadata region */
            ret = local_io_set_config(priv);
            if(ret != 0){
                r = errno;
                (*config->log)(LOG_ERR, "failed to write meta data region to block device file.");
                goto fail3;
            }

            size_t nwords;
            u_int *bitmap;

            int num_blocks = priv->handle->metadata.size / priv->handle->metadata.blocksize;
            nwords = (num_blocks + (sizeof(*bitmap) * BITS_IN_CHAR) - 1) / (sizeof(*bitmap) * BITS_IN_CHAR);
            if ((priv->handle->local_bitmap = calloc(nwords, sizeof(*bitmap))) == NULL)
                err(1, "calloc");

            /* initialize bit map */
            ret = write_bitmap(priv);
            if(ret != 0){
                 r = errno;
                (*config->log)(LOG_DEBUG, "write_bitmap returned = %d", ret);
                goto fail3;
            }

        }
        else{
            r = EINVAL; 
            goto fail3;
        }
    }
    else{
         r = errno;
         goto fail2;
    }

    pthread_mutex_unlock(&priv->mutex); 
    return cb;

fail3:
    blk_dev_close(priv->handle);
    pthread_mutex_unlock(&priv->mutex);
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
    struct local_io_private *const priv = cb->data;

    return (*priv->inner->flush)(cb);
}

static void 
local_io_destroy(struct cloudbacker_store *cb)
{
    struct local_io_private *const priv = cb->data;

    pthread_mutex_lock(&priv->mutex);

    write_bitmap(priv);
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
local_io_write_block(struct cloudbacker_store *cb, cb_block_t block_num, const void *src, u_char *md5,check_cancel_t *check_cancel, void *arg)
{
    struct local_io_private *const priv = cb->data;
    struct localStore_io_conf *const config = priv->local_conf;
    blk_dev_handle_t handle = priv->handle; 
    int num_blocks = handle->metadata.size / handle->metadata.blocksize;

    /* Sanity check */
    if (config->block_size == 0 || block_num >= num_blocks)
        return EINVAL;

    /* Detect zero blocks (if not done already by upper layer) */
    if (src != NULL) {
        if (local_io_is_zero_block(src, config->block_size))
            src = NULL;        
    }

    /* Logging */
    (*config->log)(LOG_DEBUG, "local_io: write block %0*jx %s",
                               CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num, src == NULL ? " (zero block)" : "");


    pthread_mutex_lock(&priv->mutex);
    /* compute the offset as per the mounted file system block size and block device block size */
    off_t offset = 0;
    int r = 0;
    offset = (priv->handle->metadata.blocksize *(block_num+1));

    if (priv->handle->local_bitmap != NULL) {
        const int bits_per_word = sizeof(*priv->handle->local_bitmap) * BITS_IN_CHAR;
        const int word = block_num / bits_per_word;
        const int bit = 1 << (block_num % bits_per_word);

        if (src == NULL) {
            priv->stats.empty_blocks_written++;
            r = 0;
        }
        else{
            priv->stats.normal_blocks_written++;
            priv->handle->local_bitmap[word] |= bit;
            pthread_mutex_unlock(&priv->mutex);
            return local_io_write(priv, block_num, offset, config->block_size, src);
        }
        pthread_mutex_unlock(&priv->mutex);
        (*config->log)(LOG_DEBUG, "local_io: write block priv->local_bitmap[word] = %u",priv->handle->local_bitmap[word]);
        return r;
    }
    pthread_mutex_unlock(&priv->mutex);
    return 0;

}

static int
local_io_write(struct local_io_private *const priv, cb_block_t block_num, u_int off, u_int len, const void *src)
{
    struct localStore_io_conf *const config = priv->local_conf;

    pthread_mutex_lock(&priv->mutex);

    assert(src == NULL);

    size_t sofar;
    ssize_t r;

    for (sofar = 0; sofar < len; sofar += r) {
        const off_t posn = off + sofar;

        if ((r = blk_dev_write(((const char *)src + sofar), priv->handle, off + sofar, len - sofar)) == -1) {
            (*config->log)(LOG_ERR, "error writing block device file at offset %ju: %s", (uintmax_t)posn, strerror(r));
            goto fail;
        }
    }
    if(sofar != len){
        (*config->log)(LOG_ERR, "error writing block device file, file is truncated");
        goto fail;
    }
    
    pthread_mutex_unlock(&priv->mutex);
    return 0;

fail:
    pthread_mutex_unlock(&priv->mutex);
    return EIO;
}

static int
local_io_read_block(struct cloudbacker_store *const cb, cb_block_t block_num, void *dest, u_char *actual_md5, const u_char *expect_md5, int strict)
{
    struct local_io_private *const priv = cb->data;
    struct localStore_io_conf *const config = priv->local_conf;
    blk_dev_handle_t handle = priv->handle;
    int num_blocks = handle->metadata.size / handle->metadata.blocksize;

    off_t offset = 0;
    offset = (priv->handle->metadata.blocksize *(block_num+1));

    /* Sanity check */
    if (config->block_size == 0 || block_num >= num_blocks)
        return EINVAL;

    /* Logging */
    (*config->log)(LOG_DEBUG, "local_io: read block %0*jx ",
                               CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num);

    pthread_mutex_lock(&priv->mutex);
    if (priv->handle->local_bitmap != NULL) {
        const int bits_per_word = (sizeof(*priv->handle->local_bitmap) * BITS_IN_CHAR);
        const int word = block_num / bits_per_word;
        const int bit = 1 << (block_num % bits_per_word);

        /* if bit is set, then block exists in local store, else read from cloud store or test store(if --test flag is used) */
        if ((priv->handle->local_bitmap[word] & bit) != 0) {
            (*config->log)(LOG_DEBUG, "reading block from local store: %0*jx", CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num); 

            priv->stats.local_normal_blocks_read++;
            pthread_mutex_unlock(&priv->mutex);     
            return local_io_read(priv, block_num, offset, config->block_size, dest);
        }
        else {
            (*config->log)(LOG_DEBUG, "reading block from cloud/test store: %0*jx", CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num);
            priv->stats.cloud_normal_blocks_read++;
            pthread_mutex_unlock(&priv->mutex);
            return (*priv->inner->read_block)(priv->inner, block_num, dest, actual_md5, expect_md5, strict);
        }
    }
    pthread_mutex_unlock(&priv->mutex);
    return 0;
}

/*
 * Read a block.
 */
static int
local_io_read(struct local_io_private *const priv, cb_block_t block_num, u_int off, u_int len, void *dest)
{
    struct localStore_io_conf *const config = priv->local_conf;

    pthread_mutex_lock(&priv->mutex);

    assert(dest == NULL);

    size_t sofar;
    size_t r;


    /* perform read */
    for (sofar = 0; sofar < len; sofar += r) {
        const off_t posn = off + sofar;

        if ((r = blk_dev_read(((char *)dest + sofar), priv->handle, off + sofar, len - sofar)) == -1) {
            (*config->log)(LOG_ERR, "error reading block device file at offset %ju: %s",
              (uintmax_t)posn, strerror(r));
            goto fail;
        }
        if (r == 0) {
            (*config->log)(LOG_ERR, "error reading block device file at offset %ju: file is truncated",(uintmax_t)posn);
            goto fail;
        }
    }

    if(sofar != len){
        (*config->log)(LOG_ERR, "error reading block device file, file is truncated");
        memset(dest,0,len);
        goto fail;
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

static int
local_io_set_config(struct local_io_private *const priv)
{

    struct localStore_io_conf *const config = priv->local_conf;

    int r, errcode;
    
    if(priv->handle == NULL){
        /* Sanity check */
        if(config->blk_device_path == NULL)
            return EINVAL;
  
       /* set block device access flags */
       int flags = O_DIRECT | O_SYNC;
       if(priv->readOnly)
           flags =  /*flags | */O_RDONLY;
       else
           flags =  /*flags | */O_RDWR;

       priv->handle = blk_dev_open(config->blk_device_path, flags);
       if(priv->handle == NULL){
           return EINVAL;
       }

       if(priv->handle->fd < 0) {
           (*config->log)(LOG_ERR, "invalid file handle");
           return EINVAL;
       }
    }

    /* stat the block device file */
    struct stat device_Stat;
    if(stat(config->blk_device_path,&device_Stat) < 0)
        return EINVAL;

    size_t size, blocksize;
    ioctl(priv->handle->fd, BLKPBSZGET, &blocksize);
    ioctl(priv->handle->fd, BLKGETSIZE64, &size);

    priv->handle->metadata.magic = MAGIC_STRING;
    priv->handle->metadata.major_version = (long)major(device_Stat.st_rdev);
    priv->handle->metadata.minor_version = (long)minor(device_Stat.st_rdev);

    ioctl(priv->handle->fd, BLKPBSZGET, &priv->handle->metadata.blocksize);// check if logical block size is required
    ioctl(priv->handle->fd, BLKGETSIZE64, &priv->handle->metadata.size);

    priv->handle->metadata.bitmap_start_offset = sizeof(priv->handle->metadata);

    int num_blocks = priv->handle->metadata.size / priv->handle->metadata.blocksize;
    priv->handle->metadata.bitmap_size = ((num_blocks / BITS_IN_CHAR)*sizeof(*priv->handle->local_bitmap));

    /* we need conf->num_blocks bits to set the bits, which is conf->num_blocks/BITS_IN_CHAR bytes */
    priv->handle->metadata.data_start_block_offset = METADATA_BLOCK_OFFSET + sizeof(priv->handle->metadata) + priv->handle->metadata.bitmap_size;

    if(strlen(config->prefix) > MAX_PREFIX_LENGTH){
        (*config->log)(LOG_ERR, "max prefix length allowed is %d", MAX_PREFIX_LENGTH);
        return EINVAL;
    }

    priv->handle->metadata.app_prefix_len = strlen(config->prefix);
    if(priv->handle->metadata.app_prefix_len > 0)
         strncpy(priv->handle->metadata.app_prefix, config->prefix, strlen(config->prefix));
    else
         memset(priv->handle->metadata.app_prefix,0,sizeof(priv->handle->metadata.app_prefix));

    (*config->log)(LOG_INFO, "write meta data region block");
    
    /* validate given block device before setting the configuration */
    r = local_io_validate_config(priv);
    if(r == DEVICE_CANT_BE_USED)
       return EINVAL;

    /* write 512 bytes to the disk, which is meta data region or like super block at METADATA_BLOCK_OFFSET byte offset */
    r = blk_dev_write(&(priv->handle->metadata), priv->handle, METADATA_BLOCK_OFFSET, sizeof(priv->handle->metadata));
    if((r == 0) || (r < 0 ) || ((r > 0) && (r != sizeof(priv->handle->metadata)))){
       errcode = errno;
       (*config->log)(LOG_ERR, "failed to write meta data region block: %s", strerror(errcode));
       return errcode;
    }

    (*config->log)(LOG_INFO, "Successfully written block device meta data region.");
    return 0;
}

static blk_dev_handle_t 
local_io_get_config(struct local_io_private *const priv)
{

    struct localStore_io_conf *const config = priv->local_conf;

    int r, errcode;

    if(priv->handle == NULL){
        /* Sanity check */
        if(config->blk_device_path == NULL)
            return NULL;

        /* set block device access flags */
        int flags = O_DIRECT | O_SYNC;
        if(priv->readOnly)
            flags =  /*flags | */O_RDONLY;
        else
            flags =  /*flags | */O_RDWR;

        priv->handle = blk_dev_open(config->blk_device_path, flags);
        if(priv->handle == NULL){
            return NULL;
        }

        if(priv->handle->fd < 0) {
            (*config->log)(LOG_ERR, "invalid file handle");
            return NULL;
        }
    }

    // read meta data region or like super block
    r = blk_dev_read((char *)&(priv->handle->metadata), priv->handle, METADATA_BLOCK_OFFSET, sizeof(priv->handle->metadata));
    if(r==0){
        errcode = errno;
        (*config->log)(LOG_ERR, "No data to read in meta data region of block device file: %s", strerror(errcode));
        return priv->handle;
    }
    if((r < 0 ) || ((r > 0) && (r != sizeof(priv->handle->metadata)))){
        errcode = errno;
        (*config->log)(LOG_ERR, "Error reading meta data region of block device file: %s", strerror(errcode));
        return NULL;
    }

    (*config->log)(LOG_INFO, "Completed reading the block device meta data region.");
    return priv->handle;
   
}

static int
local_io_validate_config(struct local_io_private *const priv)
{

    struct localStore_io_conf *const config = priv->local_conf;
    blk_dev_handle_t bd = priv->handle;

    /* validate meta data read from device */
    if( bd->metadata.magic != MAGIC_STRING) {
        (*config->log)(LOG_ERR, "block device meta data block magic string != application meta data magic string.");
        return DEVICE_NOT_INITIALIZED;
    }

    if(bd->metadata.major_version > MAJOR_NUMBER && bd->metadata.minor_version < MINOR_NUMBER)
        return DEVICE_CANT_BE_USED;
    else if(bd->metadata.major_version <= MAJOR_NUMBER && bd->metadata.minor_version > MINOR_NUMBER) // may be this condition is not required
        return DEVICE_CANT_BE_USED;
    
    if(strlen(bd->metadata.app_prefix) !=  strlen(config->prefix)){
        (*config->log)(LOG_ERR, "block device meta data block app prefix != config data prefix.");
        return DEVICE_CANT_BE_USED;
    }
    if(strncasecmp(bd->metadata.app_prefix, config->prefix, strlen(config->prefix)) != 0){
       (*config->log)(LOG_ERR, "block device meta data block app prefix != config data prefix.");
       return DEVICE_CANT_BE_USED;
    }

    (*config->log)(LOG_INFO, "validation successful for meta data region.");

    return DEVICE_INITIALIZED;
 
}
/* write the bitmap memory to device metadata region */
static int
write_bitmap(struct local_io_private *const priv)
{

    struct localStore_io_conf *const config = priv->local_conf;
    blk_dev_handle_t bd = priv->handle;
    int r = 0, errcode = 0;

    if(bd->fd < 0) {
        (*config->log)(LOG_ERR, "invalid file handle");
        return EINVAL;
    }

    int num_blocks =  bd->metadata.size / bd->metadata.blocksize;
    int block = 0;
    for(block=0; block< num_blocks; block++){
        const int bits_per_word = sizeof(*bd->local_bitmap) * BITS_IN_CHAR;
        const int word = block / bits_per_word;

        r = blk_dev_write((char *)&(priv->handle->local_bitmap[word]), bd,
                           bd->metadata.bitmap_start_offset+(block*sizeof(*bd->local_bitmap)),sizeof(*bd->local_bitmap));
        if((r == 0) || (r < 0 ) || ((r > 0) && (r != sizeof(*bd->local_bitmap)))){
            errcode = errno;
            (*config->log)(LOG_ERR, "failed to write bitmap to block device: %s", strerror(errcode));
            return errcode;
        }
    }

    (*config->log)(LOG_INFO, "Successfully written bitmap to block device.");
    return 0;
}

/* read the bitmap from device metadata region into memory */
static int
read_bitmap(struct local_io_private *const priv)
{

    struct localStore_io_conf *const config = priv->local_conf;
    blk_dev_handle_t bd = priv->handle;

    int r = 0, errcode = 0;

    if(bd->fd < 0) {
        (*config->log)(LOG_ERR, "invalid file handle");
        return EINVAL;
    }

    int num_blocks =  bd->metadata.size / bd->metadata.blocksize;
    int block = 0;
    for(block=0; block< num_blocks; block++){
        const int bits_per_word = sizeof(*bd->local_bitmap) * BITS_IN_CHAR;
        const int word = block / bits_per_word;

        r = blk_dev_read((char *)&(priv->handle->local_bitmap[word]), bd, 
                         bd->metadata.bitmap_start_offset+(block*sizeof(*bd->local_bitmap)),sizeof(*bd->local_bitmap));
        if((r == 0) || (r < 0 ) || ((r > 0) && (r != sizeof(*bd->local_bitmap)))){
            errcode = errno;
            (*config->log)(LOG_ERR, "failed to read bitmap from block device: %s", strerror(errcode));
            return errcode;
        }
    }

    (*config->log)(LOG_INFO, "Successfully read bitmap from block device.");
    return 0;
}

                                 
