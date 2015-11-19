/*
 * cloudbacker - FUSE-based single file backing store
 *
 * Copyright 2008-2011 Archie L. Cobbs <archie@dellroad.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 
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
#include <malloc.h>

#define MAX_PREFIX_LENGTH               128
#define ALIGNMENT                       512
#define DEVICE_INITIALIZED              0
#define DEVICE_NOT_INITIALIZED          1
#define DEVICE_CANT_BE_USED             2

#define MAGIC_STRING                    0xC104DBAC
#define MAJOR_NUMBER                    1
#define MINOR_NUMBER                    0

static int blk_dev_set_config(blk_dev_handle_t handle);
static int blk_dev_get_config(blk_dev_handle_t handle);
static int blk_dev_validate_config(blk_dev_handle_t handle);
static int blk_dev_read_bitmap(blk_dev_handle_t handle);
static int blk_dev_write_bitmap(blk_dev_handle_t handle);

extern blk_dev_handle_t blk_dev_open(char *path, int readOnly, size_t blockSize, size_t size, char *prefix, log_func_t *log )
{

    int r = 0;

    if(path == NULL){
        errno = EINVAL;
        goto fail0;
    }

    /* stat the block device file */
    struct stat device_Stat;
    if(stat(path,&device_Stat) < 0)
        goto fail0;
    
    blk_dev_handle_t handle = NULL;
    if((r = posix_memalign ((void *)&handle, ALIGNMENT, sizeof(blk_dev_t))) != 0){
        r = errno;
        err(1, "posix_memalign(): %s", strerror(r)); 
        goto fail0;
    }

    if(handle == NULL){
        r = errno;
        err(1, "posix_memalign(): %s", strerror(r));
        goto fail0;
    }

    handle->cb_blocksize = blockSize;
    handle->cb_size = size;
    handle->prefix = strdup(prefix);
    handle->blk_dev_path = strdup(path);
    handle->log = log;

    /* set block device access flags */
    int flags = O_DIRECT | O_SYNC;
    if(readOnly)
        flags =  flags | O_RDONLY;
    else
        flags =  flags | O_RDWR;

    handle->fd = open(path, flags);
    if(handle->fd < 0) {
        (*handle->log)(LOG_ERR, "invalid file handle");
        goto fail1;
    }
    
    r = blk_dev_get_config(handle);
    if(r != 0){
         goto fail1;
    }
    if(handle != NULL){

        int ret = blk_dev_validate_config(handle);
        if(ret == DEVICE_INITIALIZED){

            size_t nwords;
            u_int *bitmap;

            int num_blocks = handle->cb_size / handle->cb_blocksize;
            nwords = (num_blocks + (sizeof(*bitmap) * BITS_IN_CHAR) - 1) / (sizeof(*bitmap) * BITS_IN_CHAR);
            if((ret = posix_memalign ((void *)&(handle->local_bitmap), ALIGNMENT, nwords*sizeof(*bitmap))) != 0){
                ret = errno;
                (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(ret));
                goto fail1;
            }

            if(handle->local_bitmap == NULL){
                 r = errno;
                 (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
                 goto fail1;
             }
            /* metadata read from meta data region is valid, now read the bitmap from device into memory */
            ret = blk_dev_read_bitmap(handle);
            if(ret != 0){
                 errno = ret;
                (*handle->log)(LOG_ERR,"blk_dev_read_bitmap() failed with error: %s",strerror(ret));
                goto fail1;
            }
        }
        else if(ret == DEVICE_NOT_INITIALIZED){

            /* initialize metadata region */
            ret = blk_dev_set_config(handle);
            if(ret != 0){
                r = errno;
                (*handle->log)(LOG_ERR, "failed to write meta data region to block device file: %s",strerror(ret));
                goto fail1;
            }

            size_t nwords;
            u_int *bitmap;
			
            int num_blocks = handle->cb_size / handle->cb_blocksize;
            nwords = (num_blocks + (sizeof(*bitmap) * BITS_IN_CHAR) - 1) / (sizeof(*bitmap) * BITS_IN_CHAR);
            if((ret = posix_memalign ((void *)&(handle->local_bitmap), ALIGNMENT, nwords*sizeof(*bitmap))) != 0){
                ret = errno;
                (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(ret));
                goto fail1;
            }

            if(handle->local_bitmap == NULL){
                r = errno;
                (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
                goto fail1;
            }

            /* initialize bit map */
            ret = blk_dev_write_bitmap(handle);
            if(ret != 0){
                errno = ret;
                (*handle->log)(LOG_ERR,"blk_dev_write_bitmap() failed with error: %s",strerror(ret));
                goto fail1;
            }

        }
        else{
            r = EINVAL;
            goto fail1;
        }
    }
    else{
         errno = r;
         goto fail1;
    }

    return handle;

fail1:
    blk_dev_close(handle); 
fail0:
    handle = NULL;
    return handle;
}

extern int blk_dev_close(blk_dev_handle_t handle)
{
    if(handle != NULL){
        blk_dev_write_bitmap(handle);
        close(handle->fd);

        if(handle->local_bitmap != NULL)
            free(handle->local_bitmap);

        free(handle);
    }

    return 0;
}

extern size_t blk_dev_write(const void *buf, blk_dev_handle_t handle, off_t byte_offset, size_t nbytes)
{
    int r = 0, errcode;
    if(handle->fd < 0)
        return -1;

    void *aligned_buf=NULL;
    if((r = posix_memalign (&aligned_buf, ALIGNMENT, nbytes)) != 0){
        r = errno;
        (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(r));
        return -1;
    }

    if(aligned_buf == NULL){
        r = errno;
        (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
        return -1;
    }

    memset(aligned_buf, 0, nbytes);
    memcpy(aligned_buf,buf,nbytes);

    /* write the buffer */
    r = pwrite(handle->fd,aligned_buf, nbytes, byte_offset);
    if(r==0){
        errcode = r;
        (*handle->log)(LOG_ERR, "No data written to block device file");
        return -1;
    }
    if((r < 0 ) || ((r > 0) && (r != nbytes))){
        errcode = errno;
        (*handle->log)(LOG_ERR, "Error writing to block device file at offset %u: %s", byte_offset, strerror(errcode));
        return -1;
    }

    
    free(aligned_buf);
    return r;
}

extern size_t blk_dev_read(char *buf, blk_dev_handle_t handle, off_t byte_offset, size_t nbytes)
{
    int r = 0, errcode;
    if(handle->fd < 0)
        return -1;

    void *aligned_buf=NULL;
    if((r = posix_memalign (&aligned_buf, ALIGNMENT, nbytes)) != 0){
        r = errno;
        (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(r));
        return -1;
    }

    if(aligned_buf == NULL){
        r = errno;
         (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
        return -1;
    }
    memset(aligned_buf,0, nbytes);
    /* read the buffer */
    r = pread(handle->fd, aligned_buf, nbytes, byte_offset);
   
    memcpy(buf, aligned_buf,nbytes);
    free(aligned_buf);

    if(r==0){
        errcode = r;
        (*handle->log)(LOG_ERR, "No data to read from block device file");
        return -1;
    }
    if((r < 0 ) || ((r > 0) && (r != nbytes))){
        errcode = errno;
        (*handle->log)(LOG_ERR, "Error reading block device file at offset %u: %s", byte_offset, strerror(errcode));
        return -1;
    }

    return r;
}

static int
blk_dev_set_config(blk_dev_handle_t handle)
{

    int r, errcode;

    if(handle->fd < 0) {
        (*handle->log)(LOG_ERR, "invalid file handle");
        return EINVAL;
    }
    
    assert(handle->blk_dev_path == NULL);

    /* stat the block device file */
    struct stat device_Stat;
    if(stat(handle->blk_dev_path,&device_Stat) < 0)
        return EINVAL;
     
     /* initialize metadata and set */
    memset((void*)&(handle->metadata), 0, sizeof(handle->metadata));

    handle->metadata.magic = MAGIC_STRING;
    handle->metadata.major_version = (long)major(device_Stat.st_rdev);
    handle->metadata.minor_version = (long)minor(device_Stat.st_rdev);

    ioctl(handle->fd, BLKPBSZGET, &handle->metadata.bd_blocksize);
    ioctl(handle->fd, BLKGETSIZE64, &handle->metadata.bd_size);

    handle->metadata.alignment = ALIGNMENT;

    handle->metadata.bitmap_start_byteoffset = sizeof(handle->metadata); 

    int num_blocks = handle->cb_size / handle->cb_blocksize;
    handle->metadata.bitmap_size = (num_blocks / BITS_IN_CHAR);

    /* we need conf->num_blocks bits to set the bits, which is conf->num_blocks/BITS_IN_CHAR bytes */
    off_t tmp = (METADATA_BLOCK_OFFSET + handle->metadata.bitmap_start_byteoffset + handle->metadata.bitmap_size) / ALIGNMENT;
    handle->metadata.data_start_byteoffset = ALIGNMENT * (tmp+1); // block aligned

    if(strlen(handle->prefix) > MAX_PREFIX_LENGTH){
        (*handle->log)(LOG_ERR, "max prefix length allowed is %d", MAX_PREFIX_LENGTH);
        return EINVAL;
    }

    handle->metadata.app_prefix_len = strlen(handle->prefix);
    if(handle->metadata.app_prefix_len > 0)
         strncpy(handle->metadata.app_prefix, handle->prefix, strlen(handle->prefix));
    else
         memset(handle->metadata.app_prefix,0,sizeof(handle->metadata.app_prefix));

   memset(handle->metadata.dummy,0,sizeof(handle->metadata.dummy));
    
   (*handle->log)(LOG_INFO, "write meta data region block");

    /* validate given block device before setting the configuration */
    r = blk_dev_validate_config(handle);
    if(r == DEVICE_CANT_BE_USED)
       return EINVAL;

    void *buf=NULL;
    if((r = posix_memalign (&buf, ALIGNMENT, sizeof(handle->metadata))) != 0){
        r = errno;
        (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(r));
        return r;
    }

    if(buf == NULL){
        r = errno;
        (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
        return r;
    }

   memcpy(buf,(const void*)&(handle->metadata),sizeof(handle->metadata));

    /* write 512 bytes to the disk, which is meta data region or like super block at METADATA_BLOCK_OFFSET byte offset */
    r = pwrite(handle->fd, buf, sizeof(handle->metadata),  METADATA_BLOCK_OFFSET);
    free(buf);
    if(r==0){
        errcode = r;
        (*handle->log)(LOG_ERR, "wrote %d bytes of  metadata to block device file",r);
        return EIO;
    }
    if((r < 0 ) || ((r > 0) && (r != sizeof(handle->metadata)))){
       errcode = errno;
       (*handle->log)(LOG_ERR, "failed to write meta data region block: %s", strerror(errcode));
       return errcode;
    }
    (*handle->log)(LOG_INFO, "Successfully written block device meta data region.");
	 return 0;
}

static int
blk_dev_get_config(blk_dev_handle_t handle)
{

    int r, errcode;
    if(handle->fd < 0) {
        (*handle->log)(LOG_ERR, "invalid file handle");
        return EINVAL;
    }

    void *buf = NULL;
    if((r = posix_memalign (&buf, ALIGNMENT, sizeof(handle->metadata))) != 0){
        r = errno;
        (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(r));
        return r;
    }

    if(buf == NULL){
        r = errno;
        (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
        return r;
    }
    
    // read meta data region or like super block
    r = pread(handle->fd, buf, sizeof(handle->metadata),  METADATA_BLOCK_OFFSET);
    memcpy((void*)&(handle->metadata), buf, sizeof(handle->metadata));
    free(buf);
    if(r==0){
        errcode = r;
        (*handle->log)(LOG_ERR, "No data to read in meta data region of block device file");
        return EIO;
    }
    if((r < 0 ) || ((r > 0) && (r != sizeof(handle->metadata)))){
        errcode = errno;
        (*handle->log)(LOG_ERR, "Error reading meta data region of block device file: %s", strerror(errcode));
        return EIO;
    }

    (*handle->log)(LOG_INFO, "Completed reading the block device meta data region.");
    return 0;

}

static int
blk_dev_validate_config(blk_dev_handle_t handle)
{

    /* validate meta data read from device */
    if( handle->metadata.magic != MAGIC_STRING) {
        (*handle->log)(LOG_ERR, "block device meta data block magic string != application meta data magic string.");
        return DEVICE_NOT_INITIALIZED;
    }

    if(handle->metadata.major_version > MAJOR_NUMBER && handle->metadata.minor_version < MINOR_NUMBER)
        return DEVICE_CANT_BE_USED;
    else if(handle->metadata.major_version <= MAJOR_NUMBER && handle->metadata.minor_version > MINOR_NUMBER) // may be this condition is not required
        return DEVICE_CANT_BE_USED;

    if(strlen(handle->metadata.app_prefix) !=  strlen(handle->prefix)){
        (*handle->log)(LOG_ERR, "block device meta data block app prefix != config data prefix.");
        return DEVICE_CANT_BE_USED;
    }
    if(strncasecmp(handle->metadata.app_prefix, handle->prefix, strlen(handle->prefix)) != 0){
       (*handle->log)(LOG_ERR, "block device meta data block app prefix != config data prefix.");
       return DEVICE_CANT_BE_USED;
    }

    if(handle->cb_blocksize < handle->metadata.bd_blocksize){
        (*handle->log)(LOG_ERR, "block device block size is not compatible with file system block size.");
        return DEVICE_CANT_BE_USED;
    }
    
    if(handle->cb_size > handle->metadata.bd_size){
        (*handle->log)(LOG_ERR, "block device size is not compatible with file system size.");
        return DEVICE_CANT_BE_USED;
    }

   
    (*handle->log)(LOG_INFO, "validation successful for meta data region.");
    return DEVICE_INITIALIZED;
}

/* write the bitmap memory to device metadata region */
static int
blk_dev_write_bitmap(blk_dev_handle_t handle)
{

    int r = 0, errcode = 0;

    if(handle != NULL) {

        if(handle->fd < 0) {
            (*handle->log)(LOG_ERR, "invalid file handle");
            return EINVAL;
        }
        if(handle->local_bitmap == NULL) {
            (*handle->log)(LOG_ERR, "local_bitmap is not valid");
            return EINVAL;
        }

        void *buf=NULL;
        u_int *bitmap;
        int num_blocks =  handle->cb_size / handle->cb_blocksize;
        size_t nwords = (num_blocks + (sizeof(*bitmap) * BITS_IN_CHAR) - 1) / (sizeof(*bitmap) * BITS_IN_CHAR);

        size_t tmp = (nwords*sizeof(*bitmap)) / ALIGNMENT;
        size_t size = ALIGNMENT + (tmp*ALIGNMENT);  // size bytes will be allocated
         
        if((r = posix_memalign (&buf, ALIGNMENT, size)) != 0){
            r = errno;
            (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(r));
            return r;
        }

        if(buf == NULL){
            r = errno;
            (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
            return r; 
        }

        memset(buf,0, size);

        cb_block_t block = 0;
        for(block=0; block< num_blocks; block++){
	    const int bits_per_word = sizeof(*handle->local_bitmap) * BITS_IN_CHAR;
	    const int word = block / bits_per_word;
	    memcpy(((char*)buf) + sizeof(*handle->local_bitmap),(const void*)&(handle->local_bitmap[word]),sizeof(*handle->local_bitmap));
            //(*handle->log)(LOG_DEBUG," write (handle->local_bitmap[word]): %0*jx, %u", CB_BLOCK_NUM_DIGITS, (uintmax_t)block, (handle->local_bitmap[word]));
        }

        r = pwrite(handle->fd, buf, size, handle->metadata.bitmap_start_byteoffset);
        free(buf);
        if((r == 0) || (r < 0 ) || ((r > 0) && (r != size))){
            errcode = errno;
           (*handle->log)(LOG_ERR, "failed to write bitmap to block device: %s", strerror(errcode));
           return errcode;
        }
        
        (*handle->log)(LOG_INFO, "Successfully written bitmap to block device.");
    }
    return 0;
}

/* read the bitmap from device metadata region into memory */
static int
blk_dev_read_bitmap( blk_dev_handle_t handle)
{

    int r = 0, errcode = 0;

    if(handle != NULL) {
     
        if(handle->fd < 0) {
            (*handle->log)(LOG_ERR, "invalid file handle");
            return EINVAL;
        }

        void *buf=NULL;
        u_int *bitmap;
        int num_blocks =  handle->cb_size / handle->cb_blocksize;
        size_t nwords = (num_blocks + (sizeof(*bitmap) * BITS_IN_CHAR) - 1) / (sizeof(*bitmap) * BITS_IN_CHAR);

        size_t tmp = (nwords*sizeof(*bitmap)) / ALIGNMENT;
        size_t size = ALIGNMENT + (tmp*ALIGNMENT);  // size bytes will be allocated

        if((r = posix_memalign (&buf, ALIGNMENT, size)) != 0){
            r = errno;
            (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(r));
            return r;
        }

        if(buf == NULL){
            r = errno;
            (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
            return r;
        }
        memset(buf,0, size);
        r = pread(handle->fd, buf, size,  handle->metadata.bitmap_start_byteoffset);
        if((r == 0) || (r < 0 ) || ((r > 0) && (r != size))){
           errcode = errno;
           (*handle->log)(LOG_ERR, "failed to read bitmap from block device: %s", strerror(errcode));
           free(buf);
           return errcode;
        }

        cb_block_t block = 0;
        for(block=0; block< num_blocks; block++){
            const int bits_per_word = sizeof(*handle->local_bitmap) * BITS_IN_CHAR;
            const int word = block / bits_per_word;
            memcpy((void*)&(handle->local_bitmap[word]), ((char*)buf) + sizeof(*handle->local_bitmap), sizeof(*handle->local_bitmap));
            // (*handle->log)(LOG_DEBUG," read (handle->local_bitmap[word]): %0*jx, %u", CB_BLOCK_NUM_DIGITS, (uintmax_t)block, (handle->local_bitmap[word]));

        }
        free(buf);
        (*handle->log)(LOG_INFO, "Successfully read bitmap from block device.");

     }
     return 0;
}



