
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
#include "cb_http_io.h"
#include "cloudbacker_config.h"
#include "erase.h"
#include "reset.h"

int
main(int argc, char **argv)
{
    const struct fuse_operations *fuse_ops;
    struct cloudbacker_config *config;

    /* Get configuration */
/*
 #if RUN_TESTS  
    //if ((config = cloudbacker_get_config(argc, argv)) == NULL)
      //  return 1;
   cloudbacker_config_Test_Init();
   return 0;
#else
    if ((config = cloudbacker_get_config(argc, argv)) == NULL)
        return 1;
#endif
*/
   if ((config = cloudbacker_get_config(argc, argv)) == NULL)
        return 1;
    /* Handle `--erase' flag */
    if (config->erase) {
        if (cloudbacker_erase(config) != 0)
            return 1;
        return 0;
    }

    /* Handle `--reset' flag */
    if (config->reset) {
        if (cloudbacker_reset(config) != 0)
            return 1;
        return 0;
    }

    /* Get FUSE operation hooks */
    fuse_ops = fuse_ops_create(&config->fuse_ops);

    /* Start */
    (*config->log)(LOG_INFO, "s3backer process %lu for %s started", (u_long)getpid(), config->mount);
    return fuse_main(config->fuse_args.argc, config->fuse_args.argv, fuse_ops, NULL);
}

