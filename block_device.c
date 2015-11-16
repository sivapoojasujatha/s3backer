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

extern blk_dev_handle_t blk_dev_open(char *path, int flags)
{

    int r = 0;

    /* stat the block device file */
    struct stat device_Stat;
    if(stat(path,&device_Stat) < 0)
        return NULL;
    
    blk_dev_handle_t handle = calloc(1, sizeof(blk_dev_t));
    if(handle == NULL){
        r = errno;
        err(1, "calloc(): %s", strerror(r));
        return handle;
    }
    
    /* open file */
    handle->fd = open(path, flags);
    if(handle->fd < 0){
        r = errno;
        goto fail1;
    }
    
    return handle;
fail1:
    blk_dev_close(handle); 
    handle = NULL;
    return handle;
}

extern int blk_dev_close(blk_dev_handle_t handle)
{
    close(handle->fd);

    if(handle->local_bitmap != NULL)
        free(handle->local_bitmap);

    free(handle);

    return 0;
}

extern size_t blk_dev_write(const void *buf, blk_dev_handle_t handle, off_t byte_offset, size_t nbytes)
{

    if(handle->fd < 0)
        return EINVAL;

    /* write the buffer */
    return pwrite(handle->fd, buf, nbytes, byte_offset);
}

extern size_t blk_dev_read(char *buf, blk_dev_handle_t handle, off_t byte_offset, size_t nbytes)
{

    if(handle->fd < 0)
        return EINVAL;

    /* read the buffer */
    return pread(handle->fd, buf, nbytes, byte_offset);
}


