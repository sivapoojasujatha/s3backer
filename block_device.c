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
#include <assert.h>

#define METADATA_BLOCK_OFFSET           0
#define MAX_PREFIX_LENGTH               128

/* Device meta data errors */
#define DEVICE_INITIALIZED              0
#define DEVICE_NOT_INITIALIZED          1
#define DEVICE_CANT_BE_USED             2

/* device meta data validation parameters */
#define MAGIC_STRING                    0xC104DBAC
#define MAJOR_VER_NUMBER                1
#define MINOR_VER_NUMBER                0

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
            u_int         magic;                                /* must be first in this specific order */
            u_int         major_version, minor_version;         /* device major and minor versions */
            size_t        size;                                 /* configured file system size */
            size_t        blocksize;                            /* configured block size */
            size_t        device_size;                          /* block device size */
            off_t         data_start_byteoffset;                /* offset in bytes from where data blocks are written/read from device */
            int           app_prefix_len;                       /* length of the prefix string */
            char          app_prefix[128];                      /* string, --prefix="xyz" */

            /* bit map related stuff */
            off_t         bitmap_start_byteoffset;              /* byte offset where bitmap is stored */
            size_t        bitmap_size;                          /* size of bitmap = no. of bytes in block device starting at bitmap_start_offset */

            /* block alignment stuff */
            size_t        alignment;                             /* to align block device IO operations */
        } data;
    };
} __attribute__ ((packed));                                      /* byte packed */

/*
 * block device opaque handle
 */
struct blk_dev_t {
    struct blk_dev_meta    meta;                                 /* block device meta data */
    int                    fd;
    log_func_t             *log;
    size_t                 cb_blocksize;                         /* specified while mounting */
    size_t                 cb_size;                              /* specified while mounting */
    char                   *prefix;
    char                   *blk_dev_path;
};

static int blk_dev_init_meta(struct local_io_private *priv);
static int blk_dev_set_config(blk_dev_handle_t handle);
static int blk_dev_get_config(blk_dev_handle_t handle);
static int blk_dev_validate_config(blk_dev_handle_t handle);
static int blk_dev_read_bitmap(struct local_io_private *priv);
static int blk_dev_write_bitmap(struct local_io_private *priv);

/*
static int write_buf(void *buf, blk_dev_handle_t handle, off_t off, size_t len );
static int read_buf(void *buf, blk_dev_handle_t handle, off_t off, size_t len );
*/
extern blk_dev_handle_t blk_dev_open(struct local_io_private *priv, char *path, int readOnly, size_t blockSize,
				     size_t size, char *prefix, log_func_t *log )
{
    int r = 0, ret = 0;
    blk_dev_handle_t handle = NULL;    

    if(path == NULL){
        r = EINVAL;        
        goto fail0;
    }
    
    if((r = posix_memalign ((void *)&handle, ALIGNMENT, sizeof(struct blk_dev_t))) != 0){
        err(1, "posix_memalign(): %s", strerror(r));
        goto fail0;
    }
   
    if(handle == NULL){
        r = errno;
        err(1, "posix_memalign(): %s", strerror(r));
        goto fail0;
    }
   
    priv->handle = handle;
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
        ret = errno;
        (*handle->log)(LOG_ERR, "bad device file descriptor : %s", strerror(ret)); 
        goto fail1;
    }
    
    r = blk_dev_get_config(handle);
    if(r != 0){
        goto fail1;
    }

    ret = blk_dev_validate_config(handle);
    if (ret == DEVICE_INITIALIZED) {
        /* size must be multiple of ALIGNMENT */
        assert((handle->meta.data.bitmap_size % ALIGNMENT) == 0);
        if((ret = posix_memalign ((void *)&(priv->bitmap), ALIGNMENT, handle->meta.data.bitmap_size)) != 0){
            (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(ret));
            goto fail1;
        }
        if(priv->bitmap == NULL){
            r = EINVAL;
           (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
           goto fail1;
        }

        /*
         * metadata read from meta data region is valid, now read the bitmap
         * from device into memory
         */
         ret = blk_dev_read_bitmap(priv);
         if(ret != 0){
             (*handle->log)(LOG_ERR,"blk_dev_read_bitmap() failed with error: %s", strerror(ret));
             goto fail1;
         }
    }
    else if(ret == DEVICE_NOT_INITIALIZED){
        
        /* initialize metadata structure in memory */
        ret = blk_dev_init_meta(priv);
        if (ret) {
            (*handle->log)(LOG_ERR,"blk_dev_init_meta() failed with error: %s",strerror(ret));
            goto fail1;
        }

        /* bitmap size is multiple of ALIGNMENT - calculated by */
        assert((handle->meta.data.bitmap_size % ALIGNMENT) == 0);
		
        if((ret = posix_memalign ((void *)&(priv->bitmap), ALIGNMENT, handle->meta.data.bitmap_size)) != 0){
            (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(ret));
            goto fail1;
        }
		
        if(priv->bitmap == NULL){
            r = EINVAL;
            (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
            goto fail1;
        }		
		
        /* initially, the bitmap is all zeros */
        memset(priv->bitmap, 0, handle->meta.data.bitmap_size);

        /* write the empty bitmap to disk */
        ret = blk_dev_write_bitmap(priv);
        if(ret != 0){
            (*handle->log)(LOG_ERR,"blk_dev_write_bitmap() failed with error: %s", strerror(ret));
            goto fail1;
        }
		
        /* initialize metadata region after initializing the bitmap */
        ret = blk_dev_set_config(handle);
        if(ret != 0){
            (*handle->log)(LOG_ERR, "failed to write meta data region to block device file: %s",strerror(ret));
            goto fail1;
        }
        /* disk initialization done - the disk is fully initialized, including the bitmap and the metadata */
    }
    else{
        r = EINVAL;
        goto fail1;
    }
    priv->handle = handle;
    return handle;

fail1:
    blk_dev_close(priv); 
fail0:
    handle = NULL;
    return handle;
}

/* close block device file and free the handle */
extern int blk_dev_close(struct local_io_private *priv)
{

    blk_dev_handle_t handle = priv->handle;

    if(handle != NULL){

        /* write memory bitmap back to device */
        blk_dev_write_bitmap(priv);
  
        /* close file */
        (*handle->log)(LOG_INFO, "closing block device file");
        close(handle->fd);

        free(handle);
     }

     return 0;
}

extern int blk_dev_flush(struct local_io_private *priv)
{
    blk_dev_handle_t handle = priv->handle;

    if(handle != NULL)
        return (fsync(handle->fd));

    return 0;
}

/*
 * write the buffer to block device
 */ 
extern size_t blk_dev_write(struct local_io_private *priv, const void *buf, off_t byte_offset, size_t nbytes)
{
    int r = 0, errcode=0;
    void *aligned_buf = NULL;

    blk_dev_handle_t handle = priv->handle;

    /* Sanity checks */
    if (handle->fd < 0) {
        errcode = EINVAL;
        (*handle->log)(LOG_ERR, "bad device file descriptor : %s",strerror(errcode));
        return -1;
    }

    /* byte_offset is in bytes which is already computed to blocksize * block_num
     * assume data_start_byteoffset = 512 byte offset and nbytes=4096bytes
     * b0 will be written at 512+(4096*0) = 512 byte offset
     * b1 will be written at 512+(4096*1) = 4608 byte offset and so on
     */
    off_t offset = handle->meta.data.data_start_byteoffset + byte_offset; 

    /* check if we have to write beyond size */ 
    if ( (offset + nbytes) > handle->meta.data.device_size ){
       return -1;
    }
	
    /* maye be problem when performing partial block IO 
     * if (offset % ALIGNMENT || nbytes % ALIGNMENT) {
        (*handle->log)(LOG_ERR, "unaligned offset %"PRIi64" or nbytes %"PRIu64"", offset, nbytes);
        return -1; 
    }*/  
   
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

    /* need aligned buffers for direct device I/O
     * if buf == NULL, then consider it as zero block or may be delete block.
     * Hence, fill entire aligned_buf with zeroes and write to disk
     */
    if(buf != NULL)	
        memcpy(aligned_buf,buf,nbytes);
    else
        memset(aligned_buf,0,nbytes);		

    r = pwrite(handle->fd, aligned_buf, nbytes, offset);
    free(aligned_buf);
    if(r != nbytes){
        if (r < 0)
            errcode = errno;
        else
            errcode = EIO;
        (*handle->log)(LOG_ERR, "Error writing to block device file at offset %"PRIi64": %s", offset, strerror(errcode));
        r = -1;
    }
    return r;

}

/*
 * read the buffer from block device 
 */ 
extern size_t blk_dev_read(struct local_io_private *priv, char *buf, off_t byte_offset, size_t nbytes)
{

    blk_dev_handle_t handle = priv->handle;
    int r = 0, errcode = 0;
    void *aligned_buf=NULL;

    /* Sanity checks */
    if (handle->fd < 0) {
        errcode = EINVAL;
        (*handle->log)(LOG_ERR, "bad device file descriptor : %s",strerror(errcode));
        return -1;
    }

    /* byte_offset is in bytes which is already computed to blocksize * block_num
     * assume data_start_byteoffset = 512 byte offset and nbytes=4096 bytes
     * b0 will be written at 512+(4096*0) = 512 byte offset
     * b1 will be written at 512+(4096*1) = 4608 byte offset and so on
     */
    off_t offset = handle->meta.data.data_start_byteoffset + byte_offset;

    /* check if we have to read beyond device size */
    if ( offset + nbytes > handle->meta.data.device_size )
        return EINVAL;

    /* maye be problem when performing partial block IO 
     * if (offset % ALIGNMENT || nbytes % ALIGNMENT) {
        (*handle->log)(LOG_ERR, "unaligned offset %"PRIi64" or nbytes %"PRIu64"", byte_offset, nbytes);
        return -1;
    }*/

    if((r = posix_memalign (&aligned_buf, ALIGNMENT, nbytes)) != 0){
        r = errno;
        (*handle->log)(LOG_ERR, "aligned memory block allocation failed : %s", strerror(r));
        return -1;
    }

    if (aligned_buf == NULL) {
        r = errno;
        (*handle->log)(LOG_ERR, "posix_memalign() failed : %s", strerror(r));
        return -1;
    }
  
    r = pread(handle->fd, aligned_buf, nbytes, offset);    
    memcpy(buf, aligned_buf,nbytes);
    free(aligned_buf);
    if(r != nbytes){
        if (r < 0)
            errcode = errno;
        else
            errcode = EIO;
        (*handle->log)(LOG_ERR, "Error reading from block device file at offset %"PRIi64": %s", offset, strerror(errcode));
        r = -1;
    }

    return r;
}

/*
 * Initialize the metadata structure in memory
 */
static int
blk_dev_init_meta(struct local_io_private *priv)
{

    blk_dev_handle_t handle = priv->handle;

    int errcode = 0;

    if(handle->fd < 0) {
        errcode = EINVAL;
        (*handle->log)(LOG_ERR, "bad device file descriptor : %s",strerror(errcode));
        return errcode;
    }
    
    /* initialize metadata */
    assert(((uint64_t)&handle->meta.data.magic % ALIGNMENT) == 0);
    memset((void*)&(handle->meta.data.magic), 0, sizeof(handle->meta));

    handle->meta.data.magic = MAGIC_STRING;
    handle->meta.data.major_version = MAJOR_VER_NUMBER;
    handle->meta.data.minor_version = MINOR_VER_NUMBER;

    handle->meta.data.blocksize = handle->cb_blocksize;
    handle->meta.data.size = handle->cb_size;

    size_t size=0;

    /* read block device size */
    ioctl(handle->fd, BLKGETSIZE64, &size);
    handle->meta.data.device_size = size;

    handle->meta.data.alignment = ALIGNMENT;

    handle->meta.data.bitmap_start_byteoffset = sizeof(handle->meta); 
    assert((handle->meta.data.bitmap_start_byteoffset % ALIGNMENT) == 0);

    int num_blocks = handle->cb_size / handle->cb_blocksize;

    /*
     * Not all the blocks on the block device are for writing data,
     * there is the metadata block, and the bitmap, and therefore, the actual
     * number of bitmap bits is less than db_size/db_blocksize
     * But we will neglect this difference and will allocate the bitmap for 
     * all the blocks in the device regardless
     */
    size_t nwords = (num_blocks + sizeof(*priv->bitmap) * BITS_IN_CHAR - 1) / (sizeof(*priv->bitmap) * BITS_IN_CHAR - 1);
  
    handle->meta.data.bitmap_size = (nwords * sizeof(*priv->bitmap) + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
    assert((handle->meta.data.bitmap_size % ALIGNMENT) == 0);

    /* calculate data offset on the block device, make sure it is aligned properly */
    handle->meta.data.data_start_byteoffset = (METADATA_BLOCK_OFFSET + handle->meta.data.bitmap_start_byteoffset + handle->meta.data.bitmap_size);

    assert((handle->meta.data.data_start_byteoffset % ALIGNMENT) == 0);

    if (strlen(handle->prefix) > MAX_PREFIX_LENGTH) {
        (*handle->log)(LOG_ERR, "max prefix length allowed is %d", MAX_PREFIX_LENGTH);
        return EINVAL;
    }

    handle->meta.data.app_prefix_len = strlen(handle->prefix);
    if(handle->meta.data.app_prefix_len > 0)
        strncpy(handle->meta.data.app_prefix, handle->prefix, strlen(handle->prefix));
    else
        memset(handle->meta.data.app_prefix,0,sizeof(handle->meta.data.app_prefix));

    return 0;
}

/*
 * Write the metadata section to disk
 */
static int
blk_dev_set_config(blk_dev_handle_t handle)
{
    int r, errcode;

    if(handle->fd < 0) {
        errcode = EINVAL;
       (*handle->log)(LOG_ERR, "bad device file descriptor : %s",strerror(errcode));
       return errcode;
    }

    (*handle->log)(LOG_INFO, "write meta data region block");
   
    /* validate given block device before setting the configuration */
    r = blk_dev_validate_config(handle);
    if(r == DEVICE_CANT_BE_USED)
        return EINVAL;

    /*
     * the code assumes that metadata region is aligned at ALIGNMENT boundary,
     * and it is a multiple of ALIGNMENT - assert this assumption
     */
    assert(((uint64_t)&handle->meta.data.magic % ALIGNMENT) == 0);
    assert((sizeof(handle->meta) % ALIGNMENT) == 0);

    r = pwrite(handle->fd, &handle->meta.data, sizeof(handle->meta),  METADATA_BLOCK_OFFSET);

    if (r != sizeof(handle->meta)){
        if (r < 0)
            errcode = errno;
        else
            errcode = EIO;
        (*handle->log)(LOG_ERR, "failed to write meta data region block: %s", strerror(errcode));
        return errcode;
    }

    (*handle->log)(LOG_INFO, "Successfully written block device meta data region.");
    return 0;
}

/*
 * Read the metadata section from disk
 */
static int
blk_dev_get_config(blk_dev_handle_t handle)
{

    int r, errcode;
    if(handle->fd < 0) {
        errcode = EINVAL;
        (*handle->log)(LOG_ERR, "bad device file descriptor : %s",strerror(errcode));
        return errcode;
    }

    /* The code assumes that metadata is aligned at ALIGNMENT boundary */
    assert(((uint64_t)&handle->meta.data.magic % ALIGNMENT) == 0);

    /* The code assumes that metadata size is a multiple of ALIGNMENT */
    assert((sizeof(handle->meta) % ALIGNMENT) == 0);

    // read meta data region
    r = pread(handle->fd, &handle->meta.data, sizeof(handle->meta),  METADATA_BLOCK_OFFSET);

    if (r != sizeof(handle->meta)){
        if (r < 0)
            errcode = errno;
        else
            errcode = EIO;
        (*handle->log)(LOG_ERR, "Error reading meta data region of block device file: %s", strerror(errcode));
        return EIO;
    }

    (*handle->log)(LOG_INFO, "Completed reading the block device meta data region.");
    return 0;
}

/*
 * See if the metadata section is valid and we can interpret it
 *
 */
static int
blk_dev_validate_config(blk_dev_handle_t handle)
{

    /* validate meta data read from device */
    if( handle->meta.data.magic != MAGIC_STRING) {
        (*handle->log)(LOG_ERR, "block device meta data block magic string != application meta data magic string.");
        return DEVICE_NOT_INITIALIZED;
    }

    /* verify the metadata version */
    if ((handle->meta.data.major_version > MAJOR_VER_NUMBER) ||
        (handle->meta.data.major_version = MAJOR_VER_NUMBER &&
        handle->meta.data.minor_version > MINOR_VER_NUMBER)) {
        (*handle->log)(LOG_ERR, "block device meta data version %d.%d is higher than the known %d.%d.",
                     	       handle->meta.data.major_version, handle->meta.data.minor_version,
		               MAJOR_VER_NUMBER, MINOR_VER_NUMBER);
        return DEVICE_CANT_BE_USED;
    }

    /* need this as strncmp will not compare strings if either of prefix length is zero */
    if(handle->meta.data.app_prefix_len != strlen(handle->prefix)) {
        (*handle->log)(LOG_ERR, "block device meta data block app prefix %s != config data prefix %s.", 
                                strlen(handle->meta.data.app_prefix) > 0 ? handle->meta.data.app_prefix : "null",
                                strlen(handle->prefix) > 0 ? handle->prefix : "null");
        return DEVICE_CANT_BE_USED;
    }
    if (strcmp(handle->meta.data.app_prefix, handle->prefix) != 0) {
        (*handle->log)(LOG_ERR, "block device meta data block app prefix != config data prefix.");
        return DEVICE_CANT_BE_USED;
    }

    /* get block device block size and size
     * validate against configured file system block size and filesystem size
     */

    size_t blk_size=0, size=0; 
 
    /* read block device specific size and block size */
    ioctl(handle->fd, BLKPBSZGET, &blk_size);
    ioctl(handle->fd, BLKGETSIZE64, &size);

    /* validate block size */
    if ((handle->cb_blocksize < blk_size) || (handle->cb_blocksize != handle->meta.data.blocksize) || (handle->cb_blocksize % blk_size != 0)) {
        (*handle->log)(LOG_ERR, "block device metadata block size %"PRIi64" is not compatible with the filesystem block size %"PRIi64"",
                                handle->meta.data.blocksize, handle->cb_blocksize);

        (*handle->log)(LOG_INFO,"incorrect block size: block device block size: %"PRIi64""
                                ": meta data block size: %"PRIi64" : file system block size: %"PRIi64"" ,
                                blk_size, handle->meta.data.blocksize, handle->cb_blocksize);
        return DEVICE_CANT_BE_USED;
    }
  
    /*
     * validate size and check size compatibility 
     * cloudbacker mounted file system size should always be (block device size - (sizeof(meta.data)+meta.data.bitmap_size))
     */
    if ((handle->cb_size > size) || (handle->cb_size != handle->meta.data.size) ||
        (handle->cb_size > (size - (sizeof(handle->meta.data) + handle->meta.data.bitmap_size)))) {
        (*handle->log)(LOG_ERR, "block device metadata size %"PRIi64" is not compatible with the filesystem size %"PRIi64"",
                   	         size, handle->cb_size);
        (*handle->log)(LOG_INFO, "incorrect size: block device size: %"PRIi64""
                                 ": meta data size: %"PRIi64" : file system size: %"PRIi64"" ,
                                 size, handle->meta.data.size, handle->cb_size); 
        (*handle->log)(LOG_INFO, "file system size should be slightly(1MB or 2MB) less than the block device size");
        return DEVICE_CANT_BE_USED;
    }

    /*
     * validate proper alignment of the metadata, bitmap, and the data
     * sections on the device
     */
    if ((handle->meta.data.bitmap_start_byteoffset % handle->meta.data.alignment) ||
        (handle->meta.data.bitmap_size % handle->meta.data.alignment) ||
        (handle->meta.data.data_start_byteoffset % handle->meta.data.alignment)) {
        (*handle->log)(LOG_INFO, "invalid disk section alignment or size: "
                                 "%"PRIi64" : %"PRIi64" : %"PRIi64"",
                                 handle->meta.data.bitmap_start_byteoffset,
                                 handle->meta.data.bitmap_size,
                                 handle->meta.data.data_start_byteoffset);
    }

    (*handle->log)(LOG_INFO, "validation successful for meta data region.");
    return DEVICE_INITIALIZED;
}

/*
 * Write the bitmap from memory to the device bitmap region
 */
static int
blk_dev_write_bitmap(struct local_io_private *priv)
{
    blk_dev_handle_t handle = priv->handle;

    int r = 0, errcode = 0;

    if (handle == NULL) {
        (*handle->log)(LOG_ERR, "block device handle is not valid");
        return EINVAL;
    }

    if(handle->fd < 0) {
        errcode = EINVAL;
        (*handle->log)(LOG_ERR, "bad device file descriptor : %s",strerror(errcode));
        return errcode;
    }

    if(priv->bitmap == NULL) {
        (*handle->log)(LOG_ERR, "bitmap is not valid");
        return EINVAL;
    }

    assert(((uint64_t)priv->bitmap % ALIGNMENT) == 0);
    assert((handle->meta.data.bitmap_size % ALIGNMENT) == 0);
	
    r = pwrite(handle->fd, priv->bitmap, handle->meta.data.bitmap_size, handle->meta.data.bitmap_start_byteoffset);
    if (r != handle->meta.data.bitmap_size) {
        if (r < 0)
            errcode = errno;
        else
           errcode = EIO;
        (*handle->log)(LOG_ERR, "failed to write bitmap to block device: %s", strerror(errcode));
        return errcode;
    }
        
    (*handle->log)(LOG_INFO, "Successfully written bitmap to block device.");

    return 0;
}

/*
 * Read the bitmap from device bitmap region into memory
 */
static int
blk_dev_read_bitmap( struct local_io_private *priv)
{
    blk_dev_handle_t handle = priv->handle;

    int r = 0, errcode = 0;
  
    if (handle == NULL) {
        (*handle->log)(LOG_ERR, "block device handle is not valid");
        return EINVAL;
    }
     
    if (handle->fd < 0) {
        errcode = EINVAL;
        (*handle->log)(LOG_ERR, "bad device file descriptor : %s",strerror(errcode));
        return errcode;
    }
	
    r = pread(handle->fd, &priv->bitmap[0], handle->meta.data.bitmap_size, handle->meta.data.bitmap_start_byteoffset);
    if (r != handle->meta.data.bitmap_size) {
        if (r < 0)
            errcode = errno;
        else
            errcode = EIO;
        (*handle->log)(LOG_ERR, "failed to read bitmap from block device: %s", strerror(errcode));
        return errcode;
    }

    (*handle->log)(LOG_INFO, "Successfully read bitmap from block device.");

    return 0;
}


