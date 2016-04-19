
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
#include "block_cache.h"
#include "ec_protect.h"
#include "fuse_ops.h"
#include "cloudbacker_config.h"
#include "http_gio.h"
#include "erase.h"
#include "reset.h"

int
main(int argc, char **argv)
{
    const struct fuse_operations *fuse_ops;
    struct cb_config *config;

    /* Get configuration */
    if ((config = cloudbacker_get_config(argc, argv)) == NULL)
	err(errno, "invalid configuration");

    /* Handle `--erase' flag */
    if (config->erase) {
        if (cloudbacker_erase(config) != 0 && errno)
	    err(errno, "bucket erase");
        return 0;
    }

    /* Handle `--reset' flag */
    if (config->reset) {
        if (cloudbacker_reset(config) != 0 && errno)
	    err(errno, "bucket mount reset");
        return 0;
    }

    /* Get FUSE operation hooks */
    fuse_ops = fuse_ops_create(&config->fuse_ops);

    /* Start */
    (*config->log)(LOG_INFO, "cloudbacker process %lu for %s started", (u_long)getpid(), config->mount);
    return fuse_main(config->fuse_args.argc, config->fuse_args.argv, fuse_ops, NULL);
}

