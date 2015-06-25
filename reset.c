
/*
 * s3backer - FUSE-based single file backing store via Amazon S3
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
#include "block_cache.h"
#include "ec_protect.h"
#include "fuse_ops.h"
#include "s3b_http_io.h"
#include "test_io.h"
#include "cloudbacker_config.h"
#include "reset.h"

int
cloudbacker_reset(cloudbacker_config *config)
{
    struct cloudbacker_store *backerstore = NULL;
    int ok = 0;
    int r;

    /* Logging */
    if (!config->quiet)
        warnx("resetting mounted flag for %s", config->description);

    /* Create temporary lower layer */
    if ((backerstore = config->test ? test_io_create(&config->http_io) : http_io_create(&config->http_io)) == NULL) {
        warnx(config->test ? "test_io_create" : "http_io_create");
        goto fail;
    }

    /* Clear mounted flag */
    if ((r = (*backerstore->set_mounted)(backerstore, NULL, 0)) != 0) {
        warnx("error clearing mounted flag: %s", strerror(r));
        goto fail;
    }

    /* Success */
    if (!config->quiet)
        warnx("done");
    ok = 1;

fail:
    /* Clean up */
    if (backerstore != NULL)
        (*backerstore->destroy)(backerstore);
    return ok ? 0 : -1;
}

