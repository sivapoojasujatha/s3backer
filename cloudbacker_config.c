
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
//#include "block_device.h"
#include "gsb_http_io.h"
#include "s3b_http_io.h"
#include "test_io.h"

/****************************************************************************
 *                          DEFINITIONS                                     *
 ****************************************************************************/

/* cloudbacker default values for some configuration parameters */
#define CLOUDBACKER_DEFAULT_PWD_FILE                   ".cloudbacker_passwd"
#define CLOUDBACKER_DEFAULT_PREFIX                     ""
#define CLOUDBACKER_DEFAULT_FILENAME                   "file"
#define CLOUDBACKER_DEFAULT_STATS_FILENAME             "stats"
#define CLOUDBACKER_DEFAULT_BLOCKSIZE                  4096
#define CLOUDBACKER_DEFAULT_TIMEOUT                    30              // 30s
#define CLOUDBACKER_DEFAULT_FILE_MODE                  0600
#define CLOUDBACKER_DEFAULT_FILE_MODE_READ_ONLY        0400
#define CLOUDBACKER_DEFAULT_INITIAL_RETRY_PAUSE        200             // 200ms
#define CLOUDBACKER_DEFAULT_MAX_RETRY_PAUSE            30000           // 30s
#define CLOUDBACKER_DEFAULT_MIN_WRITE_DELAY            500             // 500ms
#define CLOUDBACKER_DEFAULT_MD5_CACHE_TIME             10000           // 10s
#define CLOUDBACKER_DEFAULT_MD5_CACHE_SIZE             10000
#define CLOUDBACKER_DEFAULT_BLOCK_CACHE_SIZE           1000
#define CLOUDBACKER_DEFAULT_BLOCK_CACHE_NUM_THREADS    20
#define CLOUDBACKER_DEFAULT_BLOCK_CACHE_WRITE_DELAY    250             // 250ms
#define CLOUDBACKER_DEFAULT_BLOCK_CACHE_TIMEOUT        0
#define CLOUDBACKER_DEFAULT_BLOCK_CACHE_MAX_DIRTY      0
#define CLOUDBACKER_DEFAULT_READ_AHEAD                 4
#define CLOUDBACKER_DEFAULT_READ_AHEAD_TRIGGER         2
#define CLOUDBACKER_DEFAULT_COMPRESSION                Z_NO_COMPRESSION
#define CLOUDBACKER_DEFAULT_CS_ENCRYPTION              "AES-128-CBC"   // default client side encryption algorithm 
#define CLOUDBACKER_DEFAULT_SS_ENCRYPTION              "AES256"        // default server side encryption algorithm


/* Storage bucket prefix */
#define S3_BUCKET_PREFIX  			   "s3://"                      /* Amazon bucket s3://mybucket */
#define GS_BUCKET_PREFIX			   "gs://"                      /* Google cloud storage bucket gs://mybucket */
#define BUCKET_PREFIX_LENGTH 			   5                            /* strlen(S3_BUCKET_PREFIX) or strlen(GS_BUCKET_PREFIX) */


/* MacFUSE setting for kernel daemon timeout */
#ifdef __APPLE__
#ifndef FUSE_MAX_DAEMON_TIMEOUT
#define FUSE_MAX_DAEMON_TIMEOUT         600
#endif
#define cbquote0(x)                    #x
#define cbquote(x)                     cbquote0(x)
#define FUSE_MAX_DAEMON_TIMEOUT_STRING  cbquote(FUSE_MAX_DAEMON_TIMEOUT)
#endif  /* __APPLE__ */

/****************************************************************************
 *                          FUNCTION DECLARATIONS                           *
 ****************************************************************************/

static print_stats_t cb_config_print_stats;

static int parse_size_string(const char *s, uintmax_t *valp);
static void unparse_size_string(char *buf, size_t bmax, uintmax_t value);
static int search_access_for(const char *file, const char *accessId, char **idptr, char **pwptr);
static int handle_unknown_option(void *data, const char *arg, int key, struct fuse_args *outargs);
static void syslog_logger(int level, const char *fmt, ...) __attribute__ ((__format__ (__printf__, 2, 3)));
static void stderr_logger(int level, const char *fmt, ...) __attribute__ ((__format__ (__printf__, 2, 3)));
static int validate_config(void);
static void dump_config(void);
static void usage(void);

/* Command line arguments validation functions */
static int validate_credentials(void);
static int (*set_credentials) (void);
static int (*validate_authVersion) (void);
static int (*validate_accessType) (void);
static int (*validate_storageClass) (void);
static int (*set_urlbuf) (void);

/* gs specific functions */
static int validate_gs_credentials(void);
static int validate_gs_authVersion(void);
static int validate_gs_accessType(void);
static int validate_gs_storageClass(void);
static int set_gs_urlbuf(void);

/* s3 specific functions */
static int validate_s3_credentials(void);
static int validate_s3_authVersion(void);
static int validate_s3_accessType(void);
static int validate_s3_storageClass(void);
static int set_s3_urlbuf(void);

/****************************************************************************
 *                          VARIABLE DEFINITIONS                            *
 ****************************************************************************/

/* Upload/download strings */
static const char *const upload_download_names[] = { "download", "upload" };

/* Valid S3 StorageClass values */
static const char *const s3_storageClasses[] = {
    SCLASS_STANDARD,                  /* For GS and S3 */
    SCLASS_S3_REDUCED_REDUNDANCY      /* for S3 */
};

/* Valid S3 access values */
static const char *const s3_acls[] = {
    S3_ACCESS_PRIVATE,
    S3_ACCESS_PUBLIC_READ,
    S3_ACCESS_PUBLIC_READ_WRITE,
    S3_ACCESS_AUTHENTICATED_READ
};

/* Valid S3 authentication types */
static const char *const s3_auth_types[] = {
    AUTH_VERSION_AWS2,
    AUTH_VERSION_AWS4
};

/* Valid GS StorageClass values */
static const char *const gs_storageClasses[] = {
    SCLASS_STANDARD,                  /* For GS and S3 */
    SCLASS_GS_NEARLINE,               /* For GS */
    SCLASS_GS_DRA                     /* For GS */
};

/* Valid GS access values */
static const char *const gs_acls[] = {
    GS_ACCESS_PRIVATE,
    GS_ACCESS_PROJECT_PRIVATE,
    GS_ACCESS_PUBLIC_READ,
    GS_ACCESS_PUBLIC_READ_WRITE,
    GS_ACCESS_AUTHENTICATED_READ,
    GS_ACCESS_BUCKET_OWNER_READ,
    GS_ACCESS_BUCKET_OWNER_FULL_CONTROL
};

/* Valid GS authentication types */
static const char *const gs_auth_types[] = {
    AUTH_VERSION_OAUTH2
};

/* Configuration structure */
static char user_agent_buf[64];
static struct cb_config config = {

    /* HTTP config */
    .http_io= {
        .accessId=			NULL,
	.accessKey=			NULL,
        .accessType=                    NULL,
        .authVersion=                   NULL,
        .ec2iam_role=                   NULL,
        .baseURL=                       NULL,
        .region=                        NULL,
        .bucket=                        NULL,
        .maxKeys=                       LIST_BLOCKS_CHUNK, /* Max blocks to be listed at a time */
        .prefix=                        CLOUDBACKER_DEFAULT_PREFIX,
	.name_hash=	                0,
        .user_agent=                    user_agent_buf,
        .compress=                      CLOUDBACKER_DEFAULT_COMPRESSION,
        .timeout=                       CLOUDBACKER_DEFAULT_TIMEOUT,
        .initial_retry_pause=           CLOUDBACKER_DEFAULT_INITIAL_RETRY_PAUSE,
        .max_retry_pause=               CLOUDBACKER_DEFAULT_MAX_RETRY_PAUSE,
        .auth.u.s3.accessId=            NULL,
        .auth.u.s3.accessKey=           NULL,
	.auth.u.s3.accessType=          NULL, /*S3BACKER_DEFAULT_ACCESS_TYPE,*/
        .auth.u.s3.ec2iam_role=         NULL, /*Amazon EC2 IAM role */
	.auth.u.s3.authVersion=         NULL, /*S3BACKER_DEFAULT_AUTH_VERSION,*/
	.auth.u.gs.clientId= 	        NULL,
	.auth.u.gs.secret_keyfile=      NULL,
	.auth.u.gs.auth_token=          NULL,
        .auth.u.gs.accessType=          NULL, /*GSBACKER_DEFAULT_ACCESS_TYPE,*/
        .auth.u.gs.authVersion=         NULL, /*GSBACKER_DEFAULT_AUTH_VERSION,*/   	 
    },    
    
    /* Local store config or Block Device config */
    .localStore_io= {
        .blk_dev_path=                  NULL,
        .blocksize=                     0,
        .size=                          0, 
    },
    
    /* "Eventual consistency" protection config */
    .ec_protect= {
        .min_write_delay=       CLOUDBACKER_DEFAULT_MIN_WRITE_DELAY,
        .cache_time=            CLOUDBACKER_DEFAULT_MD5_CACHE_TIME,
        .cache_size=            CLOUDBACKER_DEFAULT_MD5_CACHE_SIZE,
    },

    /* Block cache config */
    .block_cache= {
        .cache_size=            CLOUDBACKER_DEFAULT_BLOCK_CACHE_SIZE,
        .num_threads=           CLOUDBACKER_DEFAULT_BLOCK_CACHE_NUM_THREADS,
        .write_delay=           CLOUDBACKER_DEFAULT_BLOCK_CACHE_WRITE_DELAY,
        .max_dirty=             CLOUDBACKER_DEFAULT_BLOCK_CACHE_MAX_DIRTY,
        .timeout=               CLOUDBACKER_DEFAULT_BLOCK_CACHE_TIMEOUT,
        .read_ahead=            CLOUDBACKER_DEFAULT_READ_AHEAD,
        .read_ahead_trigger=    CLOUDBACKER_DEFAULT_READ_AHEAD_TRIGGER,
    },

    /* FUSE operations config */
    .fuse_ops= {
        .filename=              CLOUDBACKER_DEFAULT_FILENAME,
        .stats_filename=        CLOUDBACKER_DEFAULT_STATS_FILENAME,
        .file_mode=             -1,             /* default depends on 'read_only' */
    },

    /* Common stuff */
    .block_size=            0,
    .file_size=             0,
    .quiet=                 0,
    .erase=                 0,
    .no_auto_detect=        0,
    .reset=                 0,
    .log=                   syslog_logger
};

/*
 * Command line flags
 *
 * Note: each entry here is listed twice, so both version "--foo=X" and "-o foo=X" work.
 */
static const struct fuse_opt option_list[] = {
    {
        .templ=     "--accessFile=%s",
        .offset=    offsetof(struct cb_config, accessFile),
    },
    {
        .templ=     "--accessId=%s",
        .offset=    offsetof(struct cb_config, http_io.accessId),
    },
    {
        .templ=     "--accessKey=%s",
        .offset=    offsetof(struct cb_config, http_io.accessKey),
    },
    {
        .templ=     "--accessType=%s",
        .offset=    offsetof(struct cb_config, http_io.accessType),
    },
    {
        .templ=     "--accessEC2IAM=%s",
        .offset=    offsetof(struct cb_config, http_io.ec2iam_role),
    },
    {
        .templ=     "--authVersion=%s",
        .offset=    offsetof(struct cb_config, http_io.authVersion),
    },
    {
        .templ=     "--listBlocks",
        .offset=    offsetof(struct cb_config, list_blocks),
        .value=     1
    },
    {
        .templ=     "--listBlocksAsync",
        .offset=    offsetof(struct cb_config, list_blocks_async),
        .value=     1
    },
    {
        .templ=     "--baseURL=%s",
        .offset=    offsetof(struct cb_config, http_io.baseURL),
    },
    {
        .templ=     "--region=%s",
        .offset=    offsetof(struct cb_config, http_io.region),
    },
    {
        .templ=     "--blockCacheSize=%u",
        .offset=    offsetof(struct cb_config, block_cache.cache_size),
    },
    {
        .templ=     "--blockCacheSync",
        .offset=    offsetof(struct cb_config, block_cache.synchronous),
        .value=     1
    },
    {
        .templ=     "--blockCacheThreads=%u",
        .offset=    offsetof(struct cb_config, block_cache.num_threads),
    },
    {
        .templ=     "--blockCacheTimeout=%u",
        .offset=    offsetof(struct cb_config, block_cache.timeout),
    },
    {
        .templ=     "--blockCacheWriteDelay=%u",
        .offset=    offsetof(struct cb_config, block_cache.write_delay),
    },
    {
        .templ=     "--blockCacheMaxDirty=%u",
        .offset=    offsetof(struct cb_config, block_cache.max_dirty),
    },
    {
        .templ=     "--readAhead=%u",
        .offset=    offsetof(struct cb_config, block_cache.read_ahead),
    },
    {
        .templ=     "--readAheadTrigger=%u",
        .offset=    offsetof(struct cb_config, block_cache.read_ahead_trigger),
    },
    {
        .templ=     "--blockCacheFile=%s",
        .offset=    offsetof(struct cb_config, block_cache.cache_file),
    },
    {
        .templ=     "--blockCacheNoVerify",
        .offset=    offsetof(struct cb_config, block_cache.no_verify),
        .value=     1
    },
    {
        .templ=     "--blockSize=%s",
        .offset=    offsetof(struct cb_config, block_size_str),
    },
    {
        .templ=     "--maxUploadSpeed=%s",
        .offset=    offsetof(struct cb_config, max_speed_str[HTTP_UPLOAD]),
    },
    {
        .templ=     "--maxDownloadSpeed=%s",
        .offset=    offsetof(struct cb_config, max_speed_str[HTTP_DOWNLOAD]),
    },
    {
        .templ=     "--md5CacheSize=%u",
        .offset=    offsetof(struct cb_config, ec_protect.cache_size),
    },
    {
        .templ=     "--md5CacheTime=%u",
        .offset=    offsetof(struct cb_config, ec_protect.cache_time),
    },
    {
        .templ=     "--debug",
        .offset=    offsetof(struct cb_config, debug),
        .value=     1
    },
    {
        .templ=     "--debug-http",
        .offset=    offsetof(struct cb_config, http_io.debug_http),
        .value=     1
    },
    {
        .templ=     "--quiet",
        .offset=    offsetof(struct cb_config, quiet),
        .value=     1
    },
    {
        .templ=     "--erase",
        .offset=    offsetof(struct cb_config, erase),
        .value=     1
    },
    {
        .templ=     "--reset-mounted-flag",
        .offset=    offsetof(struct cb_config, reset),
        .value=     1
    },
    {
        .templ=     "--vhost",
        .offset=    offsetof(struct cb_config, http_io.vhost),
        .value=     1
    },
    {
        .templ=     "--fileMode=%o",
        .offset=    offsetof(struct cb_config, fuse_ops.file_mode),
    },
    {
        .templ=     "--filename=%s",
        .offset=    offsetof(struct cb_config, fuse_ops.filename),
    },
    {
        .templ=     "--force",
        .offset=    offsetof(struct cb_config, force),
        .value=     1
    },
    {
        .templ=     "--noAutoDetect",
        .offset=    offsetof(struct cb_config, no_auto_detect),
        .value=     1
    },
    {
        .templ=     "--initialRetryPause=%u",
        .offset=    offsetof(struct cb_config, http_io.initial_retry_pause),
    },
    {
        .templ=     "--maxRetryPause=%u",
        .offset=    offsetof(struct cb_config, http_io.max_retry_pause),
    },
    {
        .templ=     "--minWriteDelay=%u",
        .offset=    offsetof(struct cb_config, ec_protect.min_write_delay),
    },
    {
        .templ=     "--maxKeys=%u",
        .offset=    offsetof(struct cb_config, http_io.maxKeys),
    },
    {
        .templ=     "--prefix=%s",
        .offset=    offsetof(struct cb_config, http_io.prefix),
    },
    {
        .templ=     "--nameHash",
        .offset=    offsetof(struct cb_config, http_io.name_hash),
        .value=     1
    },
    {
        .templ=     "--readOnly",
        .offset=    offsetof(struct cb_config, fuse_ops.read_only),
        .value=     1
    },
    {
        .templ=     "--size=%s",
        .offset=    offsetof(struct cb_config, file_size_str),
    },
    {
        .templ=     "--statsFilename=%s",
        .offset=    offsetof(struct cb_config, fuse_ops.stats_filename),
    },
    {
        .templ=     "--storageClass=%s",
        .offset=    offsetof(struct cb_config, http_io.storageClass),        
    },
    {
        .templ=     "--cse",
        .offset=    offsetof(struct cb_config, http_io.cse),
        .value=     1
    },
    {
        .templ=     "--sse",
        .offset=    offsetof(struct cb_config, http_io.sse),
        .value=     1
    },
    {
        .templ=     "--ssl",
        .offset=    offsetof(struct cb_config, ssl),
        .value=     1
    },
    {
        .templ=     "--cacert=%s",
        .offset=    offsetof(struct cb_config, http_io.cacert),
    },
    {
        .templ=     "--insecure",
        .offset=    offsetof(struct cb_config, http_io.insecure),
        .value=     1
    },
    {
        .templ=     "--compress",
        .offset=    offsetof(struct cb_config, http_io.compress),
        .value=     Z_DEFAULT_COMPRESSION
    },
    {
        .templ=     "--compress=%d",
        .offset=    offsetof(struct cb_config, http_io.compress),
    },
    {
        .templ=     "--encrypt",
        .offset=    offsetof(struct cb_config, encrypt),
        .value=     1
    },
    {
        .templ=     "--encrypt=%s",
        .offset=    offsetof(struct cb_config, http_io.encryption),
    },
    {
        .templ=     "--keyLength=%u",
        .offset=    offsetof(struct cb_config, http_io.key_length),
    },
    {
        .templ=     "--password=%s",
        .offset=    offsetof(struct cb_config, http_io.password),
    },
    {
        .templ=     "--passwordFile=%s",
        .offset=    offsetof(struct cb_config, password_file),
    },
    {
        .templ=     "--test",
        .offset=    offsetof(struct cb_config, test),
        .value=     1
    },
    {
        .templ=     "--localStore=%s",
        .offset=    offsetof(struct cb_config, localStore_io.blk_dev_path),        
    },
    {
        .templ=     "--timeout=%u",
        .offset=    offsetof(struct cb_config, http_io.timeout),
    },
    {
        .templ=     "--directIO",
        .offset=    offsetof(struct cb_config, fuse_ops.direct_io),
        .value=     1
    },
};

/* Default flags we send to FUSE */
static const char *const cloudbacker_fuse_defaults[] = {
    "-okernel_cache",
    "-oallow_other",
    "-ouse_ino",
    "-omax_readahead=0",
    "-osubtype=cloudbacker",
    "-oentry_timeout=31536000",
    "-onegative_timeout=31536000",
    "-oattr_timeout=0",             // because statistics file length changes
    "-odefault_permissions",
#ifndef __FreeBSD__
    "-onodev",
#endif
    "-onosuid",
#ifdef __APPLE__
    "-odaemon_timeout=" FUSE_MAX_DAEMON_TIMEOUT_STRING,
#endif
/*  "-ointr", */
};

/* Size suffixes */
struct size_suffix {
    const char  *suffix;
    int         bits;
};
static const struct size_suffix size_suffixes[] = {
    {
        .suffix=    "k",
        .bits=      10
    },
    {
        .suffix=    "m",
        .bits=      20
    },
    {
        .suffix=    "g",
        .bits=      30
    },
    {
        .suffix=    "t",
        .bits=      40
    },
    {
        .suffix=    "p",
        .bits=      50
    },
    {
        .suffix=    "e",
        .bits=      60
    },
    {
        .suffix=    "z",
        .bits=      70
    },
    {
        .suffix=    "y",
        .bits=      80
    },
};

/* cloudbacker_store layers */
struct cloudbacker_store *block_cache_store;
struct cloudbacker_store *ec_protect_store;
struct cloudbacker_store *http_io_store;
struct cloudbacker_store *test_io_store;
struct cloudbacker_store *local_io_store;

/****************************************************************************
 *                      PUBLIC FUNCTION DEFINITIONS                         *
 ****************************************************************************/

struct cb_config *
cloudbacker_get_config(int argc, char **argv)
{
    const int num_options = sizeof(option_list) / sizeof(*option_list);
    struct fuse_opt dup_option_list[2 * sizeof(option_list) + 1];
    char buf[1024];
    int i, rc;

    /* Remember user creds */
    config.fuse_ops.uid = getuid();
    config.fuse_ops.gid = getgid();

    /* Set user-agent */
    snprintf(user_agent_buf, sizeof(user_agent_buf), "%s/%s/%s", PACKAGE, VERSION, cloudbacker_version);

    /* Copy passed args */
    memset(&config.fuse_args, 0, sizeof(config.fuse_args));
    for (i = 0; i < argc; i++) {
        if (fuse_opt_insert_arg(&config.fuse_args, i, argv[i]) != 0)
            err(1, "fuse_opt_insert_arg");
    }

    /* Insert our default FUSE options */
    for (i = 0; i < sizeof(cloudbacker_fuse_defaults) / sizeof(*cloudbacker_fuse_defaults); i++) {
        if (fuse_opt_insert_arg(&config.fuse_args, i + 1, cloudbacker_fuse_defaults[i]) != 0)
            err(1, "fuse_opt_insert_arg");
    }

    /* Create the equivalent fstab options (without the "--") for each option in the option list */
    memcpy(dup_option_list, option_list, sizeof(option_list));
    memcpy(dup_option_list + num_options, option_list, sizeof(option_list));
    for (i = num_options; i < 2 * num_options; i++)
        dup_option_list[i].templ += 2;
    dup_option_list[2 * num_options].templ = NULL;

    /* Parse command line flags */
    if (fuse_opt_parse(&config.fuse_args, &config, dup_option_list, handle_unknown_option) != 0)
        return NULL;

    /* Validate configuration */
    if ((rc = validate_config()) != 0)
        err(rc, "configuration validation");

    /* Set fsname based on configuration */
    snprintf(buf, sizeof(buf), "-ofsname=%s", config.description);
    if (fuse_opt_insert_arg(&config.fuse_args, 1, buf) != 0)
        err(1, "fuse_opt_insert_arg");

    /* Set up fuse_ops callbacks */
    config.fuse_ops.print_stats = cb_config_print_stats;
    config.fuse_ops.cbconf = &config;

    /* Debug */
    if (config.debug)
        dump_config();

    /* Done */
    return &config;
}

/*
 * Create the cloudbacker_store used at runtime. This method is invoked by fuse_op_init().
 */
struct cloudbacker_store *
cloudbacker_create_store(struct cb_config *conf)
{
    struct cloudbacker_store *store;
    int mounted;
    int r;

    /* Sanity check */
    if (http_io_store != NULL || test_io_store != NULL) {
        errno = EINVAL;
        return NULL;
    }

    /* Create HTTP (or test) layer */
    if (conf->test) {
        if ((test_io_store = test_io_create(&conf->http_io)) == NULL)
            return NULL;
        store = test_io_store;
    }else {
        if ((http_io_store = http_io_create(&conf->http_io)) == NULL)
            return NULL;
        store = http_io_store;
    }

     /* create localStore_io layer if --localStore=/path/to/block/device is specified */
     if(conf->localStore_io.blk_dev_path != NULL) {
         conf->localStore_io.size=conf->file_size;
         conf->localStore_io.blocksize = conf->block_size;
         conf->localStore_io.log = conf->log;
         conf->localStore_io.prefix = strdup(conf->http_io.prefix);
         conf->localStore_io.readOnly =  conf->fuse_ops.read_only; 
         if((local_io_store = local_io_create(&conf->localStore_io, store)) == NULL)
             goto fail_with_errno;
         store = local_io_store;
     }

    /* Create eventual consistency protection layer (if desired) */
    if (conf->ec_protect.cache_size > 0) {
        if ((ec_protect_store = ec_protect_create(&conf->ec_protect, store)) == NULL) 
            goto fail_with_errno;
        store = ec_protect_store;
    }

    /* Create block cache layer (if desired) */
    if (conf->block_cache.cache_size > 0) {
        if ((block_cache_store = block_cache_create(&conf->block_cache, store)) == NULL)
            goto fail_with_errno;
        store = block_cache_store;
    }


    /* Set mounted flag and check previous value one last time */
    r = (*store->set_mounted)(store, &mounted, conf->fuse_ops.read_only ? -1 : 1);
    if (r != 0) {
        (*conf->log)(LOG_ERR, "error reading mounted flag on %s: %s", conf->description, strerror(r));
        goto fail;
    }
    if (mounted) {
        if (!conf->force) {
            (*conf->log)(LOG_ERR, "%s appears to be mounted by another cloudbacker process", config.description);
            r = EBUSY;
            goto fail;
        }
    }

    /*
     * initialize block device, only if http store is mounted
     */
    if((!mounted) && (conf->localStore_io.blk_dev_path != NULL)) {     // not mounted by other process 
        r = (*store->init)(store, mounted);
        if (r != 0) {
            (*conf->log)(LOG_ERR, "error initializing block device : %s ", strerror(r));
        }
    }

    /* Done */
    return store;

fail_with_errno:
    r = errno;
fail:
    if (store != NULL)
        (*store->destroy)(store);
    block_cache_store = NULL;
    ec_protect_store = NULL;
    http_io_store = NULL;
    test_io_store = NULL;
    errno = r;
    return NULL;
}

/****************************************************************************
 *                    INTERNAL FUNCTION DEFINITIONS                         *
 ****************************************************************************/

static void
cb_config_print_stats(void *prarg, printer_t *printer)
{
    struct http_io_stats http_io_stats;
    struct local_io_stats local_io_stats;
    struct ec_protect_stats ec_protect_stats;
    struct block_cache_stats block_cache_stats;
    double curl_reuse_ratio = 0.0;
    u_int total_oom = 0;
    u_int total_curls;

    /* Get HTTP stats */
    if (http_io_store != NULL)
        http_io_get_stats(http_io_store, &http_io_stats);

    /* Get local io layer stats */
    if(local_io_store != NULL)
        local_io_get_stats(local_io_store, &local_io_stats);

    /* Get EC protection stats */
    if (ec_protect_store != NULL)
        ec_protect_get_stats(ec_protect_store, &ec_protect_stats);

    /* Get block cache stats */
    if (block_cache_store != NULL)
        block_cache_get_stats(block_cache_store, &block_cache_stats);

    /* Print stats in human-readable form */
    if (http_io_store != NULL) {
        (*printer)(prarg, "%-28s %u\n", "http_normal_blocks_read", http_io_stats.normal_blocks_read);
        (*printer)(prarg, "%-28s %u\n", "http_normal_blocks_written", http_io_stats.normal_blocks_written);
        (*printer)(prarg, "%-28s %u\n", "http_normal_bytes_written", http_io_stats.normal_bytes_written);
        (*printer)(prarg, "%-28s %u\n", "http_zero_blocks_read", http_io_stats.zero_blocks_read);
        (*printer)(prarg, "%-28s %u\n", "http_zero_blocks_written", http_io_stats.zero_blocks_written);
        if (config.list_blocks || config.list_blocks_async) {
            (*printer)(prarg, "%-28s %u\n", "http_empty_blocks_read", http_io_stats.empty_blocks_read);
            (*printer)(prarg, "%-28s %u\n", "http_empty_blocks_written", http_io_stats.empty_blocks_written);
        }
        (*printer)(prarg, "%-28s %u\n", "http_gets", http_io_stats.http_gets.count);
        (*printer)(prarg, "%-28s %u\n", "http_puts", http_io_stats.http_puts.count);
        (*printer)(prarg, "%-28s %u\n", "http_deletes", http_io_stats.http_deletes.count);
        (*printer)(prarg, "%-28s %.3f sec\n", "http_avg_get_time", http_io_stats.http_gets.count > 0 ?
          http_io_stats.http_gets.time / http_io_stats.http_gets.count : 0.0);
        (*printer)(prarg, "%-28s %.3f sec\n", "http_avg_put_time", http_io_stats.http_puts.count > 0 ?
          http_io_stats.http_puts.time / http_io_stats.http_puts.count : 0.0);
        (*printer)(prarg, "%-28s %.3f sec\n", "http_avg_delete_time", http_io_stats.http_deletes.count > 0 ?
          http_io_stats.http_deletes.time / http_io_stats.http_deletes.count : 0.0);
        (*printer)(prarg, "%-28s %u\n", "http_bad_request", http_io_stats.http_bad_request);
        (*printer)(prarg, "%-28s %u\n", "http_unauthorized", http_io_stats.http_unauthorized);
        (*printer)(prarg, "%-28s %u\n", "http_forbidden", http_io_stats.http_forbidden);
        (*printer)(prarg, "%-28s %u\n", "http_stale", http_io_stats.http_stale);
        (*printer)(prarg, "%-28s %u\n", "http_verified", http_io_stats.http_verified);
        (*printer)(prarg, "%-28s %u\n", "http_mismatch", http_io_stats.http_mismatch);
        (*printer)(prarg, "%-28s %u\n", "http_5xx_error", http_io_stats.http_5xx_error);
        (*printer)(prarg, "%-28s %u\n", "http_4xx_error", http_io_stats.http_4xx_error);
        (*printer)(prarg, "%-28s %u\n", "http_other_error", http_io_stats.http_other_error);
        (*printer)(prarg, "%-28s %u\n", "http_canceled_writes", http_io_stats.http_canceled_writes);
        (*printer)(prarg, "%-28s %u\n", "http_num_retries", http_io_stats.num_retries);
        (*printer)(prarg, "%-28s %ju.%03u sec\n", "http_total_retry_delay",
          (uintmax_t)(http_io_stats.retry_delay / 1000), (u_int)(http_io_stats.retry_delay % 1000));
        total_curls = http_io_stats.curl_handles_created + http_io_stats.curl_handles_reused;
        if (total_curls > 0)
            curl_reuse_ratio = (double)http_io_stats.curl_handles_reused / (double)total_curls;
        (*printer)(prarg, "%-28s %.4f\n", "curl_handle_reuse_ratio", curl_reuse_ratio);
        (*printer)(prarg, "%-28s %u\n", "curl_timeouts", http_io_stats.curl_timeouts);
        (*printer)(prarg, "%-28s %u\n", "curl_connect_failed", http_io_stats.curl_connect_failed);
        (*printer)(prarg, "%-28s %u\n", "curl_host_unknown", http_io_stats.curl_host_unknown);
        (*printer)(prarg, "%-28s %u\n", "curl_out_of_memory", http_io_stats.curl_out_of_memory);
        (*printer)(prarg, "%-28s %u\n", "curl_other_error", http_io_stats.curl_other_error);
        total_oom += http_io_stats.out_of_memory_errors;
    }
    if(local_io_store != NULL) {
        (*printer)(prarg, "%-28s %u\n", "local_normal_blocks_read", local_io_stats.local_normal_blocks_read);
        (*printer)(prarg, "%-28s %u\n", "local_normal_blocks_written", local_io_stats.local_normal_blocks_written);
        (*printer)(prarg, "%-28s %u\n", "local_zero_blocks_read", local_io_stats.local_zero_blocks_read);
        (*printer)(prarg, "%-28s %u\n", "local_zero_blocks_written", local_io_stats.local_zero_blocks_written);
    }
    if (block_cache_store != NULL) {
        double read_hit_ratio = 0.0;
        double write_hit_ratio = 0.0;
        u_int total_reads;
        u_int total_writes;

        total_reads = block_cache_stats.read_hits + block_cache_stats.read_misses;
        if (total_reads != 0)
            read_hit_ratio = (double)block_cache_stats.read_hits / (double)total_reads;
        total_writes = block_cache_stats.write_hits + block_cache_stats.write_misses;
        if (total_writes != 0)
            write_hit_ratio = (double)block_cache_stats.write_hits / (double)total_writes;
        (*printer)(prarg, "%-28s %u blocks\n", "block_cache_current_size", block_cache_stats.current_size);
        (*printer)(prarg, "%-28s %u blocks\n", "block_cache_initial_size", block_cache_stats.initial_size);
        (*printer)(prarg, "%-28s %.4f\n", "block_cache_dirty_ratio", block_cache_stats.dirty_ratio);
        (*printer)(prarg, "%-28s %u\n", "block_cache_read_hits", block_cache_stats.read_hits);
        (*printer)(prarg, "%-28s %u\n", "block_cache_read_misses", block_cache_stats.read_misses);
        (*printer)(prarg, "%-28s %.4f\n", "block_cache_read_hit_ratio", read_hit_ratio);
        (*printer)(prarg, "%-28s %u\n", "block_cache_write_hits", block_cache_stats.write_hits);
        (*printer)(prarg, "%-28s %u\n", "block_cache_write_misses", block_cache_stats.write_misses);
        (*printer)(prarg, "%-28s %.4f\n", "block_cache_write_hit_ratio", write_hit_ratio);
        (*printer)(prarg, "%-28s %u\n", "block_cache_verified", block_cache_stats.verified);
        (*printer)(prarg, "%-28s %u\n", "block_cache_mismatch", block_cache_stats.mismatch);
        total_oom += block_cache_stats.out_of_memory_errors;
    }
    if (ec_protect_store != NULL) {
        (*printer)(prarg, "%-28s %u blocks\n", "md5_cache_current_size", ec_protect_stats.current_cache_size);
        (*printer)(prarg, "%-28s %u\n", "md5_cache_data_hits", ec_protect_stats.cache_data_hits);
        (*printer)(prarg, "%-28s %ju.%03u sec\n", "md5_cache_full_delays",
          (uintmax_t)(ec_protect_stats.cache_full_delay / 1000), (u_int)(ec_protect_stats.cache_full_delay % 1000));
        (*printer)(prarg, "%-28s %ju.%03u sec\n", "md5_cache_write_delays",
          (uintmax_t)(ec_protect_stats.repeated_write_delay / 1000), (u_int)(ec_protect_stats.repeated_write_delay % 1000));
        total_oom += ec_protect_stats.out_of_memory_errors;
    }
    (*printer)(prarg, "%-28s %u\n", "out_of_memory_errors", total_oom);
}

static int
parse_size_string(const char *s, uintmax_t *valp)
{
    char suffix[3] = { '\0' };
    int nconv;

    nconv = sscanf(s, "%ju%2s", valp, suffix);
    if (nconv < 1)
        return -1;
    if (nconv >= 2) {
        int found = 0;
        int i;

        for (i = 0; i < sizeof(size_suffixes) / sizeof(*size_suffixes); i++) {
            const struct size_suffix *const ss = &size_suffixes[i];

            if (ss->bits >= sizeof(off_t) * 8)
                break;
            if (strcasecmp(suffix, ss->suffix) == 0) {
                *valp <<= ss->bits;
                found = 1;
                break;
            }
        }
        if (!found)
            return -1;
    }
    return 0;
}

static void
unparse_size_string(char *buf, size_t bmax, uintmax_t value)
{
    uintmax_t unit;
    int i;

    if (value == 0) {
        snprintf(buf, bmax, "0");
        return;
    }
    for (i = sizeof(size_suffixes) / sizeof(*size_suffixes); i-- > 0; ) {
        const struct size_suffix *const ss = &size_suffixes[i];

        if (ss->bits >= sizeof(off_t) * 8)
            continue;
        unit = (uintmax_t)1 << ss->bits;
        if (value % unit == 0) {
            snprintf(buf, bmax, "%ju%s", value / unit, ss->suffix);
            return;
        }
    }
    snprintf(buf, bmax, "%ju", value);
}

/**
 * Handle command-line flag.
 */
static int
handle_unknown_option(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    /* Check options */
    if (key == FUSE_OPT_KEY_OPT) {

        /* Debug flags */
        if (strcmp(arg, "-d") == 0)
            config.debug = 1;
        if (strcmp(arg, "-d") == 0 || strcmp(arg, "-f") == 0)
            config.log = stderr_logger;

        /* Version */
        if (strcmp(arg, "--version") == 0 || strcmp(arg, "-v") == 0) {
            fprintf(stderr, "%s version %s (%s)\n", PACKAGE, VERSION, cloudbacker_version);
            fprintf(stderr, "Copyright (C) 2008-2011 Archie L. Cobbs.\n");
            fprintf(stderr, "This is free software; see the source for copying conditions.  There is NO\n");
            fprintf(stderr, "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
            exit(0);
        }

        /* Help */
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0 || strcmp(arg, "-?") == 0) {
            usage();
            exit(0);
        }

        /* Unknown; pass it through to fuse_main() */
        return 1;
    }

    /* Get bucket parameter */
    if (config.http_io.bucket == NULL) {
        if ((config.http_io.bucket = strdup(arg)) == NULL)
            err(1, "strdup");
        return 0;
    }

    /* Copy mount point */
    if (config.mount == NULL) {
        if ((config.mount = strdup(arg)) == NULL)
            err(1, "strdup");
        return 1;
    }

    /* Pass subsequent paramters on to fuse_main() */
    return 1;
}

static int
search_access_for(const char *file, const char *accessId, char **idptr, char **pwptr)
{
    char buf[1024];
    FILE *fp;

    if (idptr != NULL)
        *idptr = NULL;
    if (pwptr != NULL)
        *pwptr = NULL;
    if ((fp = fopen(file, "r")) == NULL)
        return 0;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char *colon;

        if (*buf == '#' || *buf == '\0' || isspace(*buf) || (colon = strchr(buf, ':')) == NULL)
            continue;
        while (*buf != '\0' && isspace(buf[strlen(buf) - 1]))
            buf[strlen(buf) - 1] = '\0';
        *colon = '\0';
        if (accessId != NULL && strcmp(buf, accessId) != 0)
            continue;
        if (idptr != NULL && (*idptr = strdup(buf)) == NULL)
            err(1, "strdup");
        if (pwptr != NULL && (*pwptr = strdup(colon + 1)) == NULL)
            err(1, "strdup");
        fclose(fp);
        return 1;
    }
    fclose(fp);
    return 0;
}

static int
validate_config(void)
{
    struct cloudbacker_store *cb;
    const int customBaseURL = config.http_io.baseURL != NULL;
    const int customRegion = config.http_io.region != NULL;
    uintmax_t value;
    const char *s;
    char blockSizeBuf[64];
    char fileSizeBuf[64];
    struct stat sb;
    int i;
    int r;
    char sClassBuf[64];
    /* Check bucket/testdir */
    /* bucket name format gs://bucket for GS and s3://bucket for S3 respectively. */
    /* test dir format is path/to/directory */
    if(!config.test) {
        if (config.http_io.bucket == NULL) {
            warnx("no cloudbacker bucket specified");
            return -1;
        }
        if (*config.http_io.bucket == '\0' || *config.http_io.bucket == '/') {
            warnx("invalid cloudbacker bucket `%s'", config.http_io.bucket);
            return -1;
        }
        if( (strncmp(config.http_io.bucket, S3_BUCKET_PREFIX , BUCKET_PREFIX_LENGTH) ==0) && (strlen(config.http_io.bucket) > BUCKET_PREFIX_LENGTH) ) {
            config.http_io.storage_prefix = S3_STORAGE;
        }
        else if( (strncmp(config.http_io.bucket, GS_BUCKET_PREFIX , BUCKET_PREFIX_LENGTH) ==0) && (strlen(config.http_io.bucket) > BUCKET_PREFIX_LENGTH) ) {
            config.http_io.storage_prefix = GS_STORAGE;
        }
        else{
            warnx("invalid bucket name `%s'", config.http_io.bucket);
            return -1;
        }
        char justBucketName[64];    // remove bucket prefix
        strncpy(justBucketName,config.http_io.bucket+BUCKET_PREFIX_LENGTH, strlen(config.http_io.bucket));
        strcpy(config.http_io.bucket, justBucketName);          // use only bucket name for further processing
    }
    else {
        if (config.http_io.bucket == NULL) {
            warnx("no test directory specified");
            return -1;
        }
        if (stat(config.http_io.bucket, &sb) == -1) {
            warn("%s", config.http_io.bucket);
            return -1;
        }
        if (!S_ISDIR(sb.st_mode)) {
            errno = ENOTDIR;
            warn("%s", config.http_io.bucket);
            return -1;
        }
    }

    /* Check if --localStore=/dev/blkdevice argument is specified */
    if(config.localStore_io.blk_dev_path != NULL) {
        struct stat sb1;
        int retcode = stat(config.localStore_io.blk_dev_path, &sb1);
        if((retcode != 0) || ((retcode == 0) && (!S_ISBLK(sb1.st_mode)))) {
            warnx("invalid block device path '%s' or is not a block device %s", 
                   config.localStore_io.blk_dev_path, (retcode != 0) ? strerror(errno) : "");
            return -1;    
        }
    }


    /* Now we know storage type after parsing bucket name.
     * Initialize storage specific validation function pointers here
     */
    if(config.http_io.storage_prefix == GS_STORAGE){
        set_credentials = validate_gs_credentials;
        validate_authVersion = validate_gs_authVersion;
        validate_accessType = validate_gs_accessType;
        validate_storageClass = validate_gs_storageClass;
        set_urlbuf = set_gs_urlbuf;
    }
    else if(config.http_io.storage_prefix == S3_STORAGE){
        set_credentials = validate_s3_credentials;
        validate_authVersion = validate_s3_authVersion;
        validate_accessType = validate_s3_accessType;
        validate_storageClass = validate_s3_storageClass;
        set_urlbuf = set_s3_urlbuf;
    }
   
    /* check user specified maxKeys value */
    if(config.http_io.maxKeys == 0){
       warnx("invalid maxKeys value. It should be a positive integer. Using default value %u", LIST_BLOCKS_CHUNK);
       config.http_io.maxKeys = LIST_BLOCKS_CHUNK;
    }

     /* Auto-set file mode in read_only if not explicitly set */
    if (config.fuse_ops.file_mode == -1) {
        config.fuse_ops.file_mode = config.fuse_ops.read_only ?
        CLOUDBACKER_DEFAULT_FILE_MODE_READ_ONLY : CLOUDBACKER_DEFAULT_FILE_MODE;
    }
 
    /* Read credentials from accessFile or through command line arguments accessId and accesskey */
    /* Validation is not required if run with test flag */
    if(!config.test){
        if( validate_credentials() != 0){
            warnx("Invalid credentials");
            return -1;
        }
    }

    /* Uppercase encryption name for consistency */
    if (config.http_io.encryption != NULL) {
        char *t;

        if ((t = strdup(config.http_io.encryption)) == NULL)
            err(1, "strdup()");
        for (i = 0; t[i] != '\0'; i++)
            t[i] = toupper(t[i]);
        config.http_io.encryption = t;
    }


    if(config.http_io.cse && config.http_io.sse) {
       warnx("illegal flags, use either of '--cse' or '--sse' flags.");
       return -1;
    }

     /* By default sse should be enabled, if user specifies --cse flag, then disable --sse flag */
    if(!config.http_io.cse && config.http_io.storage_prefix == S3_STORAGE) {
        config.http_io.sse = 1;
        config.encrypt = 1;        /* to use default encryption cipher */
        if(config.http_io.encryption == NULL)
           config.http_io.encryption = strdup(CLOUDBACKER_DEFAULT_SS_ENCRYPTION);

        if(strncasecmp(config.http_io.encryption, CLOUDBACKER_DEFAULT_SS_ENCRYPTION, strlen(CLOUDBACKER_DEFAULT_SS_ENCRYPTION)) != 0) {
            warnx("invalid encryption cipher `%s', supported cipher is '%s'",config.http_io.encryption, CLOUDBACKER_DEFAULT_SS_ENCRYPTION);
            return -1;
        }
    }

    if(!config.http_io.cse && !config.http_io.sse && config.encrypt){
        warnx("--encrypt flag should be specified with either '--cse' or '--sse' flags.");
        return -1;
    }
    
    /* Set default or custom region */
    if (config.http_io.region == NULL)
        config.http_io.region = S3BACKER_DEFAULT_REGION;
    if (customRegion)
        config.http_io.vhost = 1;

    /* Set default base URL */
    if (config.http_io.baseURL == NULL) {
       if( set_urlbuf() != 0)
          return -1;
    }

    /* Check base URL */
    s = NULL;
    if (strncmp(config.http_io.baseURL, "http://", 7) == 0)
        s = config.http_io.baseURL + 7;
    else if (strncmp(config.http_io.baseURL, "https://", 8) == 0)
        s = config.http_io.baseURL + 8;
    if (s != NULL && (*s == '/' || *s == '\0'))
        s = NULL;
    if (s != NULL && (s = strrchr(s, '/')) == NULL) {
        warnx("base URL must end with a '/'");
        s = NULL;
    }
    if (s != NULL && s[1] != '\0') {
        warnx("base URL must end with a '/' not '%c'", s[1]);
        s = NULL;
    }
    if (s == NULL) {
        warnx("invalid base URL `%s'", config.http_io.baseURL);
        return -1;
    }

    /* Handle virtual host style URL (prefix hostname with bucket name) */
    if (config.http_io.vhost) {
        size_t buflen;
        int schemelen;
        char *buf;

        schemelen = strchr(config.http_io.baseURL, ':') - config.http_io.baseURL + 3;
        buflen = strlen(config.http_io.bucket) + 1 + strlen(config.http_io.baseURL) + 1;
        if ((buf = malloc(buflen)) == NULL)
            err(1, "malloc(%u)", (u_int)buflen);
        snprintf(buf, buflen, "%.*s%s.%s", schemelen, config.http_io.baseURL,
          config.http_io.bucket, config.http_io.baseURL + schemelen);
        config.http_io.baseURL = buf;
    }

    /* Check storage class*/
    if( validate_storageClass() != 0)
    {
       return -1;
    }

    /* check authentication version */
    if(validate_authVersion() != 0)
    {
       return -1;
    }

    /* Check access privilege */
    if( validate_accessType() != 0)
    { 
       return -1;
    } 


    /* Check filenames */
    if (strchr(config.fuse_ops.filename, '/') != NULL || *config.fuse_ops.filename == '\0') {
        warnx("illegal filename `%s'", config.fuse_ops.filename);
        return -1;
    }
    if (strchr(config.fuse_ops.stats_filename, '/') != NULL || *config.fuse_ops.stats_filename == '\0') {
        warnx("illegal stats filename `%s'", config.fuse_ops.stats_filename);
        return -1;
    }

    if(config.http_io.cse) {
        /* Apply default encryption */
        if (config.http_io.encryption == NULL && config.encrypt )
            config.http_io.encryption = strdup(CLOUDBACKER_DEFAULT_CS_ENCRYPTION);

        /* Check encryption and get key */
        if (config.http_io.encryption != NULL) {
            char pwbuf[1024];
            FILE *fp;

            if (config.password_file != NULL && config.http_io.password != NULL) {
                warnx("specify only one of `--password' or `--passwordFile'");
                return -1;
            }
            if (config.password_file == NULL && config.http_io.password == NULL) {
                if ((s = getpass("Password: ")) == NULL)
                    err(1, "getpass()");
            }
            if (config.password_file != NULL) {
                assert(config.http_io.password == NULL);
                if ((fp = fopen(config.password_file, "r")) == NULL) {
                    warn("can't open encryption key file `%s'", config.password_file);
                    return -1;
                }
                if (fgets(pwbuf, sizeof(pwbuf), fp) == NULL || *pwbuf == '\0') {
                    warnx("can't read encryption key from file `%s'", config.password_file);
                    fclose(fp);
                    return -1;
                }
                if (pwbuf[strlen(pwbuf) - 1] == '\n')
                    pwbuf[strlen(pwbuf) - 1] = '\0';
                fclose(fp);
                s = pwbuf;
           }
           if (config.http_io.password == NULL && (config.http_io.password = strdup(s)) == NULL)
                err(1, "strdup()");
           if (config.http_io.key_length > EVP_MAX_KEY_LENGTH) {
                warnx("`--keyLength' value must be positive and at most %u", EVP_MAX_KEY_LENGTH);
                return -1;
           }
       } else {
            if (config.http_io.password != NULL)
                warnx("unexpected flag `%s' (`--encrypt' was not specified)", "--password");
            else if (config.password_file != NULL)
                warnx("unexpected flag `%s' (`--encrypt' was not specified)", "--passwordFile");
            if (config.http_io.key_length != 0)
                warnx("unexpected flag `%s' (`--encrypt' was not specified)", "--keyLength");
       }

       /* We always want to compress if we are encrypting */
       if (config.http_io.encryption != NULL && config.http_io.compress == Z_NO_COMPRESSION)
           config.http_io.compress = Z_DEFAULT_COMPRESSION;

       /* Check compression level */
       switch (config.http_io.compress) {
           case Z_DEFAULT_COMPRESSION:
           case Z_NO_COMPRESSION:
               break;
           default:
               if (config.http_io.compress < Z_BEST_SPEED || config.http_io.compress > Z_BEST_COMPRESSION) {
                   warnx("illegal compression level `%d'", config.http_io.compress);
                   return -1;
               }
               break;
       }  
   }

    if ((config.ssl || config.http_io.sse) && customBaseURL && strncmp(config.http_io.baseURL, "https", 5) != 0) {
        warnx("'--baseURL' conflicts with %s", (config.ssl ? "--ssl" : (config.http_io.sse ? "--sse" : "")));
        return -1;
    }

   /* Disable md5 cache when in read only mode */
   if (config.fuse_ops.read_only) {
        config.ec_protect.cache_size = 0;
        config.ec_protect.cache_time = 0;
        config.ec_protect.min_write_delay = 0;
   }

   /* Check time/cache values */
   if (config.ec_protect.cache_size == 0 && config.ec_protect.cache_time > 0) {
       warnx("`md5CacheTime' must zero when MD5 cache is disabled");
       return -1;
   }
   if (config.ec_protect.cache_size == 0 && config.ec_protect.min_write_delay > 0) {
       warnx("`minWriteDelay' must zero when MD5 cache is disabled");
       return -1;
   }
   if (config.ec_protect.cache_time > 0
      && config.ec_protect.cache_time < config.ec_protect.min_write_delay) {
        warnx("`md5CacheTime' must be at least `minWriteDelay'");
        return -1;
    }
    if (config.http_io.initial_retry_pause > config.http_io.max_retry_pause) {
        warnx("`maxRetryPause' must be at least `initialRetryPause'");
        return -1;
    }

    /* Parse block and file sizes */
    if (config.block_size_str != NULL) {
        if (parse_size_string(config.block_size_str, &value) == -1 || value == 0) {
            warnx("invalid block size `%s'", config.block_size_str);
            return -1;
        }
        if ((u_int)value != value) {
            warnx("block size `%s' is too big", config.block_size_str);
            return -1;
        }
        config.block_size = value;
    }
    if (config.file_size_str != NULL) {
        if (parse_size_string(config.file_size_str, &value) == -1 || value == 0) {
            warnx("invalid file size `%s'", config.file_size_str);
            return -1;
        }
        config.file_size = value;
    }

    /* Parse upload/download speeds */
    for (i = 0; i < 2; i++) {
        if (config.max_speed_str[i] != NULL) {
            if (parse_size_string(config.max_speed_str[i], &value) == -1 || value == 0) {
                warnx("invalid max %s speed `%s'", upload_download_names[i], config.max_speed_str[i]);
                return -1;
            }
            if ((curl_off_t)(value / 8) != (value / 8)) {
                warnx("max %s speed `%s' is too big", upload_download_names[i], config.max_speed_str[i]);
                return -1;
            }
            config.http_io.max_speed[i] = value;
        }
        if (config.http_io.max_speed[i] != 0 && config.block_size / (config.http_io.max_speed[i] / 8) >= config.http_io.timeout) {
            warnx("configured timeout of %us is too short for block size of %u bytes and max %s speed %s bps",
              config.http_io.timeout, config.block_size, upload_download_names[i], config.max_speed_str[i]);
            return -1;
        }
    }

    /* Check block cache config */
    if (config.block_cache.cache_size > 0 && config.block_cache.num_threads <= 0) {
        warnx("invalid block cache thread pool size %u", config.block_cache.num_threads);
        return -1;
    }
    if (config.block_cache.write_delay > 0 && config.block_cache.synchronous) {
        warnx("`--blockCacheSync' requires setting `--blockCacheWriteDelay=0'");
        return -1;
    }
    if (config.block_cache.cache_size > 0 && config.block_cache.cache_file != NULL) {
        int bs_bits = ffs(config.block_size) - 1;
        int cs_bits = ffs(config.block_cache.cache_size);

        if (bs_bits + cs_bits >= sizeof(off_t) * 8 - 1) {
            warnx("the block cache is too big to fit within a single file (%u blocks x %u bytes)",
              config.block_cache.cache_size, config.block_size);
            return -1;
        }
    }

    /* Check mount point */
    if (config.erase || config.reset) {
        if (config.mount != NULL) {
            warnx("no mount point should be specified with `--erase' or `--reset-mounted-flag'");
            return -1;
        }
    } else {
        if (config.mount == NULL) {
            warnx("no mount point specified");
            return -1;
        }
    }

    /* Format descriptive string of what we're mounting */
    if (config.test) {
        snprintf(config.description, sizeof(config.description), "%s%s/%s",
          "file://", config.http_io.bucket, config.http_io.prefix);
    } else if (config.http_io.vhost)
        snprintf(config.description, sizeof(config.description), "%s%s", config.http_io.baseURL, config.http_io.prefix);
    else {
        snprintf(config.description, sizeof(config.description), "%s%s/%s",
          config.http_io.baseURL, config.http_io.bucket, config.http_io.prefix);
    }

    /* Check computed block and file sizes */
    if(config.block_size != 0 && config.file_size != 0){
        if (config.block_size != (1 << (ffs(config.block_size) - 1))) {
            warnx("block size must be a power of 2");
            return -1;
        }    
        if (config.file_size % config.block_size != 0) {
            warnx("file size must be a multiple of block size");
            return -1;
        }
        config.num_blocks = config.file_size / config.block_size;
        if (sizeof(cb_block_t) < sizeof(config.num_blocks)
            && config.num_blocks > ((off_t)1 << (sizeof(cb_block_t) * 8))) {
            warnx("more than 2^%d blocks: decrease file size or increase block size", (int)(sizeof(cb_block_t) * 8));
            return -1;
        }

        /* Check block size vs. encryption block size */
        if (config.http_io.cse && config.http_io.encryption != NULL && config.block_size % EVP_MAX_IV_LENGTH != 0) {
            warnx("block size must be at least %u when encryption is enabled", EVP_MAX_IV_LENGTH);
            return -1;
        }
    }


    /* set http IO meta data parameters */
    config.http_io.http_metadata.block_size = config.block_size;
    config.http_io.http_metadata.file_size = config.file_size;
    config.http_io.http_metadata.num_blocks = config.num_blocks;
    config.http_io.http_metadata.name_hash = config.http_io.name_hash;
    config.http_io.http_metadata.compression_level = config.http_io.compress;
    config.http_io.http_metadata.is_cs_encrypted = config.http_io.cse;
    if( config.http_io.encryption != NULL || config.encrypt){
        config.http_io.http_metadata.encryption_cipher = NULL;
        config.http_io.http_metadata.encryption_cipher = strdup(config.http_io.encryption);
        /* --encrypt flag,implies --compress flag */
        config.http_io.http_metadata.compression_level = config.http_io.compress;
    }

    /*
     * Read the meta data block (if any) to determine existing file system meta data like file and block size,
     * and compare with configured sizes (if given).
     */
    if (config.test)
        config.no_auto_detect = 1;
    if (config.no_auto_detect)
        r = ENOENT;
    else {
        config.http_io.debug = config.debug;
        config.http_io.quiet = config.quiet;
        config.http_io.log = config.log;
        if ((cb = http_io_create(&config.http_io)) == NULL)
            err(errno, "http_io_create");
        
        r = (*cb->bucket_attributes)(cb, sClassBuf); 
        /* only for GS, storage class is bucket specific */
        if( r == 0 )
            warnx("bucket storage class is %s", config.http_io.storageClass);
        if( r == 0) {
            if (!config.quiet)
                warnx("auto-detecting file system meta data like block size, total file size etc...");
            r = (*cb->meta_data)(cb);
        }
    }

    /* Check result */
    switch (r) {
    case 0:
        unparse_size_string(blockSizeBuf, sizeof(blockSizeBuf), (uintmax_t)config.http_io.http_metadata.block_size);
        unparse_size_string(fileSizeBuf, sizeof(fileSizeBuf), (uintmax_t)config.http_io.http_metadata.file_size);

        if (!config.quiet){
            warnx("auto-detection successful");

             char encryption_data[256];
            if(config.http_io.storage_prefix == S3_STORAGE){
                sprintf(encryption_data,"%s with cipher %s",
                        config.http_io.http_metadata.is_cs_encrypted ? "client side encryption" : "server side encryption",
                        config.http_io.http_metadata.encryption_cipher == NULL ? "(none)" : config.http_io.http_metadata.encryption_cipher);
            }
            else{
                if(config.http_io.http_metadata.is_cs_encrypted)
                     sprintf(encryption_data, "client side encryption with cipher %s",
                          config.http_io.http_metadata.encryption_cipher == NULL ? "(none)" : config.http_io.http_metadata.encryption_cipher);
                else
                     sprintf(encryption_data,"%s", "server side encrypion is not applicable");
            }

            warnx("block size=%s, total size=%s, name hashing='%s', compression level='%d'%s and %s",
                  blockSizeBuf, fileSizeBuf, config.http_io.http_metadata.name_hash ? "yes" : "no",
                  config.http_io.http_metadata.compression_level, config.http_io.http_metadata.compression_level == Z_DEFAULT_COMPRESSION ? "(default)" : "",
                  encryption_data);

        }
        
        /* compare block size */
        if (config.block_size == 0)
            config.block_size = config.http_io.http_metadata.block_size;
        else if (config.http_io.http_metadata.block_size != config.block_size) {
            char buf[64];

            unparse_size_string(buf, sizeof(buf), (uintmax_t)config.block_size);
            if (config.force) {
                if (!config.quiet) {
                    warnx("warning: configured block size %s != filesystem block size %s,\n"
                      "but you said `--force' so I'll proceed anyway even though your data will\n"
                      "probably not read back correctly.", buf, blockSizeBuf);
                }
            } else
                errx(1, "error: configured block size %s != filesystem block size %s", buf, blockSizeBuf);
        }
        /* compare file size */
        if (config.file_size == 0)
            config.file_size = config.http_io.http_metadata.file_size;
        else if (config.http_io.http_metadata.file_size != config.file_size) {

            char buf[64];
            unparse_size_string(buf, sizeof(buf), (uintmax_t)config.file_size);
            if (config.force) {
                if (!config.quiet) {
                    warnx("warning: configured file size %s != filesystem file size %s,\n"
                      "but you said `--force' so I'll proceed anyway even though your data will\n"
                      "probably not read back correctly.", buf,fileSizeBuf);
                }
            } else
                errx(1, "error: configured file size %s != filesystem file size %s", buf,fileSizeBuf);
        }
        /* compare name hash setting */
        if (config.http_io.name_hash == 0)
            config.http_io.name_hash = config.http_io.http_metadata.name_hash;
        else if (config.http_io.http_metadata.name_hash != config.http_io.name_hash) {
            if (config.force) {
                if (!config.quiet) {
                    warnx("warning: configured name hashing setting '%s' != filesystem name hashing "
                          "setting '%s',\nbut you said `--force' so I'll proceed anyway even though "
		          "your object names will probably not be interpreted correctly.",
		          config.http_io.name_hash ? "yes" : "no",
		          config.http_io.http_metadata.name_hash ? "yes" : "no");
                }
            } else {
                errx(1, "error: configured name hashing setting '%s' != filesystem name hashing setting '%s'",
	                config.http_io.name_hash ? "yes" : "no", config.http_io.http_metadata.name_hash ? "yes" : "no");
            }
        }

        if(config.http_io.sse && config.http_io.http_metadata.is_cs_encrypted)
            errx(1, "error: configured server side encryption, but filesystem is having client side encryption with %s cipher",
                     config.http_io.http_metadata.encryption_cipher);

         if(config.http_io.cse && !config.http_io.http_metadata.is_cs_encrypted)
            errx(1, "error: configured client side encryption, but filesystem is having server side side encryption");

            
        /* compare compression flag */
        if (config.http_io.compress == Z_NO_COMPRESSION)
            config.http_io.compress = config.http_io.http_metadata.compression_level;
        else if (config.http_io.http_metadata.compression_level != config.http_io.compress) {
            if (config.force) {
                if (!config.quiet) {
                    warnx("warning: configured compression setting '%u' != filesystem compression setting "
                          "setting '%u',\nbut you said `--force' so I'll proceed anyway even though "
                          "your object names will probably not be interpreted correctly.",
                          config.http_io.compress, config.http_io.http_metadata.compression_level);
                }                 
            } else
                errx(1, "error: configured compression setting level='%d'%s != filesystem compression level='%d'%s ", config.http_io.compress, 
                        config.http_io.compress == Z_DEFAULT_COMPRESSION ? "(default)" : "", config.http_io.http_metadata.compression_level,
                        config.http_io.http_metadata.compression_level == Z_DEFAULT_COMPRESSION ? "(default)" : "");
       }
       /* compare encryption cipher flag */       
       if (config.http_io.encryption == NULL && config.http_io.http_metadata.is_cs_encrypted) {
            config.encrypt= config.http_io.http_metadata.is_cs_encrypted;
            config.http_io.encryption = strdup(config.http_io.http_metadata.encryption_cipher);
            if( config.http_io.password == NULL)
                errx(1, "encryption password cannot be empty as file system is encrypted,\nplease specify '--encrypt' flag and provide encryption passsword using respective flag or when prompted");
        } 
        else if(config.http_io.http_metadata.is_cs_encrypted) {
            if( strcmp(config.http_io.http_metadata.encryption_cipher, config.http_io.encryption) != 0){     
        
                if (config.force) {
                    if (!config.quiet) {
                        warnx("warning: configured encryption cipher '%s' != filesystem encryption cipher "
                              "setting '%s',\nbut you said `--force' so I'll proceed anyway even though "
                              "your object names will probably not be interpreted correctly.",
                              config.http_io.encryption == NULL ? "(none)" : config.http_io.encryption ,
                              config.http_io.http_metadata.encryption_cipher == NULL ? "(none)" : config.http_io.http_metadata.encryption_cipher);
                    } 
                } else
                     errx(1, "error: configured encryption cipher '%s' != filesystem encryption cipher '%s' ",
                     config.http_io.encryption == NULL ? "(none)" : config.http_io.encryption ,
                     config.http_io.http_metadata.encryption_cipher == NULL ? "(none)" : config.http_io.http_metadata.encryption_cipher);
            }
        }
        break;

    case ENOENT:
    {
        const char *why = config.no_auto_detect ? "disabled" : "failed (new filesystem?)";
        int config_block_size = config.block_size;

        unparse_size_string(blockSizeBuf, sizeof(blockSizeBuf), (uintmax_t)config.block_size);
        unparse_size_string(fileSizeBuf, sizeof(fileSizeBuf), (uintmax_t)config.file_size);

        if (config.file_size == 0)
            errx(1, "error: auto-detection of filesystem size %s; please specify `--size'", why);
        if (config.block_size == 0){
            config.block_size = CLOUDBACKER_DEFAULT_BLOCKSIZE;
            unparse_size_string(blockSizeBuf, sizeof(blockSizeBuf), (uintmax_t)config.block_size);
            warnx("error: auto-detection of block size %s, and block size argument was not provided; using default block size '%s'", why,blockSizeBuf);
        }
        if (!config.quiet) {
            warnx("auto-detection %s", why);
            
            char encryption_data[256];
            if(config.http_io.storage_prefix == S3_STORAGE){
                sprintf(encryption_data,"%s with cipher %s", config.http_io.cse ? "client side encryption" : "server side encryption",
                     config.http_io.encryption == NULL ? "(none)" : config.http_io.encryption);
            }
            else{
                if(config.http_io.cse)
                     sprintf(encryption_data, "client side encryption with cipher %s",
                          config.http_io.encryption == NULL ? "(none)" : config.http_io.encryption);
                else
                     sprintf(encryption_data,"%s", "server side encrypion is not applicable");
            }

            warnx("using %s block size %s, file size %s, name hashing setting '%s', compression level '%d'%s and %s",
                  config_block_size == 0 ? "default" : "configured", blockSizeBuf, fileSizeBuf,
                  config.http_io.name_hash ? "yes" : "no", config.http_io.compress, config.http_io.compress == Z_DEFAULT_COMPRESSION ? "(default)" : "",
                  encryption_data);

        }


        /* write a zero data block with configured meta data, later can be used for auto detection */ 
        if (!config.no_auto_detect) {
            r = (*cb->set_meta_data)(cb, 1 /* PUT operation */);
            if(r != 0){
                errno = r;
                err(r, "can't write meta data block");
            }
        }

    }
    break;

    default:
        errno = r;
        err(r, "can't read data store meta-data");
        break;
    }

    /* destroy cloudbacker store */
    if (!config.no_auto_detect)
        (*cb->destroy)(cb);

    if (config.block_size != (1 << (ffs(config.block_size) - 1))) {
        warnx("block size must be a power of 2");
        return -1;
    }
    if (config.file_size % config.block_size != 0) {
        warnx("file size must be a multiple of block size");
        return -1;
    }
    config.num_blocks = config.file_size / config.block_size;
    if (sizeof(cb_block_t) < sizeof(config.num_blocks)
        && config.num_blocks > ((off_t)1 << (sizeof(cb_block_t) * 8))) {
        warnx("more than 2^%d blocks: decrease file size or increase block size", (int)(sizeof(cb_block_t) * 8));
        return -1;
    }


    /* Check whether already mounted */
    if (!config.test && !config.erase && !config.reset) {
        int mounted;

        config.http_io.debug = config.debug;
        config.http_io.quiet = config.quiet;
        config.http_io.log = config.log;
        if ((cb = http_io_create(&config.http_io)) == NULL)
            err(errno, "http_io_create");
        
        r = (*cb->set_mounted)(cb, &mounted, -1);
        (*cb->destroy)(cb);
        if (r != 0) {
            errno = r;
            err(r, "error reading mounted flag");
        }
        if (mounted) {
            if (!config.force)
                errx(1, "error: %s appears to be already mounted", config.description);
            if (!config.quiet) {
                warnx("warning: filesystem appears already mounted but you said `--force'\n"
                  " so I'll proceed anyway even though your data may get corrupted.\n");
            }
        }        
        
        if (!config.erase && !config.reset) {

             /* create localStore_io layer if --localStore=/path/to/block/device is specified */
            if(config.localStore_io.blk_dev_path != NULL) {
                config.localStore_io.size=config.file_size;
                config.localStore_io.blocksize = config.block_size;
                config.localStore_io.log = config.log;
                config.localStore_io.prefix = strdup(config.http_io.prefix);
                config.localStore_io.readOnly =  config.fuse_ops.read_only;
                if((cb = local_io_create(&config.localStore_io, NULL)) == NULL)
                    err(errno, "local_io_create");
            }

            /* check if device can be used */
            if((!mounted) && (config.localStore_io.blk_dev_path != NULL)) {
                r = (*cb->init)(cb, mounted);
                (*cb->destroy)(cb);
                if (r != 0) {
                   errno=r; 
                   warnx("warning: initializing block device : %s ", strerror(r));
                }
                if(config.localStore_io.block_device_status == BLK_DEV_CANNOT_BE_USED)
                    errx(1, "error: block device %s cannot be used", config.localStore_io.blk_dev_path);
            }
        }
    }

    /* Check that MD5 cache won't eventually deadlock */
    if (config.ec_protect.cache_size > 0
      && config.ec_protect.cache_time == 0
      && config.ec_protect.cache_size < config.num_blocks) {
        warnx("`md5CacheTime' is infinite but `md5CacheSize' is less than the number of blocks, so eventual deadlock will result");
        return -1;
    }

    /* No point in the caches being bigger than necessary */
    if (config.ec_protect.cache_size > config.num_blocks) {
        warnx("MD5 cache size (%ju) is greater than the total number of blocks (%ju); automatically reducing",
          (uintmax_t)config.ec_protect.cache_size, (uintmax_t)config.num_blocks);
        config.ec_protect.cache_size = config.num_blocks;
    }
    if (config.block_cache.cache_size > config.num_blocks) {
        warnx("block cache size (%ju) is greater than the total number of blocks (%ju); automatically reducing",
          (uintmax_t)config.block_cache.cache_size, (uintmax_t)config.num_blocks);
        config.block_cache.cache_size = config.num_blocks;
    }

#ifdef __APPLE__
    /* On MacOS, warn if kernel timeouts can happen prior to our own timeout */
    {
        u_int total_time = 0;
        u_int retry_pause = 0;
        u_int total_pause;

        /*
         * Determine how much total time an operation can take including retries.
         * We have to use the same exponential backoff algorithm.
         */
        for (total_pause = 0; 1; total_pause += retry_pause) {
            total_time += config.http_io.timeout * 1000;
            if (total_pause >= config.http_io.max_retry_pause)
                break;
            retry_pause = retry_pause > 0 ? retry_pause * 2 : config.http_io.initial_retry_pause;
            if (total_pause + retry_pause > config.http_io.max_retry_pause)
                retry_pause = config.http_io.max_retry_pause - total_pause;
            total_time += retry_pause;
        }

        /* Convert from milliseconds to seconds */
        total_time = (total_time + 999) / 1000;

        /* Warn if exceeding MacFUSE limit */
        if (total_time >= FUSE_MAX_DAEMON_TIMEOUT && !config.quiet) {
            warnx("warning: maximum possible I/O delay (%us) >= MacFUSE limit (%us);", total_time, FUSE_MAX_DAEMON_TIMEOUT);
            warnx("consider lower settings for `--maxRetryPause' and/or `--timeout'.");
        }
    }
#endif  /* __APPLE__ */

    /* Copy common stuff into sub-module configs */
    config.block_cache.block_size = config.block_size;
    config.block_cache.log = config.log;
    config.http_io.debug = config.debug;
    config.http_io.quiet = config.quiet;
    config.http_io.block_size = config.block_size;
    config.http_io.num_blocks = config.num_blocks;
    config.http_io.log = config.log;
    config.ec_protect.block_size = config.block_size;
    config.ec_protect.log = config.log;
    config.fuse_ops.block_size = config.block_size;
    config.fuse_ops.num_blocks = config.num_blocks;
    config.fuse_ops.log = config.log;

    /* If `--listBlocks' was given, build non-empty block bitmap */
    if (config.erase || config.reset) {
        config.list_blocks = 0;
        config.list_blocks_async = 0;
    }

    if (config.list_blocks_async && config.list_blocks) {
	warnx("cloudbacker: asynchronous block listing mode overrides synchronous one\n");
	config.list_blocks = 0;
    }

    if (config.list_blocks) {
        struct cloudbacker_store *temp_store;
        struct http_list_blocks lb;
        size_t nwords;

        /* Logging */
        if (!config.quiet) {
            fprintf(stderr, "cloudbacker: listing non-zero blocks synchronously...\n");
            fflush(stderr);
        }

        /* Create temporary lower layer */
        if ((temp_store = config.test ? test_io_create(&config.http_io) : http_io_create(&config.http_io)) == NULL)
            err(errno, config.test ? "test_io_create" : "http_io_create");

        /* Initialize bitmap */
        nwords = (config.num_blocks + (sizeof(*lb.bitmap) * 8) - 1) / (sizeof(*lb.bitmap) * 8);
        if ((lb.bitmap = calloc(nwords, sizeof(*lb.bitmap))) == NULL)
            err(1, "calloc");
        lb.print_dots = !config.quiet;
        lb.count = 0;
	lb.mutex = NULL;
        lb.async = 0;

        /* Generate non-zero block bitmap */
        assert(config.http_io.nonzero_bitmap == NULL);
        if ((r = (*temp_store->list_blocks)(temp_store, http_list_blocks_callback, &lb)) != 0)
            errx(1, "can't list blocks: %s", strerror(r));

        /* Close temporary store */
        (*temp_store->destroy)(temp_store);

        /* Save generated bitmap */
        config.http_io.nonzero_bitmap = lb.bitmap;
        config.http_io.nonzero_bitmap_complete = HTTP_IO_BITMAP_DONE;

        /* Logging */
        if (!config.quiet) {
            fprintf(stderr, "done\n");
            warnx("found %ju non-zero blocks", lb.count);
        }
    } else {
        size_t nwords;
        u_int *bitmap;

        nwords = (config.num_blocks + (sizeof(*bitmap) * 8) - 1) / (sizeof(*bitmap) * 8);
        if ((bitmap = calloc(nwords, sizeof(*bitmap))) == NULL)
            err(1, "calloc");

        config.http_io.nonzero_bitmap = bitmap;
	if (config.list_blocks_async)
	    config.http_io.nonzero_bitmap_complete = HTTP_IO_BITMAP_ASYNC;
	else
	    config.http_io.nonzero_bitmap_complete = HTTP_IO_BITMAP_NONE;
    }

    /* Done */
    return 0;
}

/* 
 * Function to read credentials from accessFile or command line arguments accessId and accesskey
 *
 * cloudbacker accessFile format
 *
 * For s3: accessFile format
 * <accessId>:<secret oraccesskey>
 *
 * For GCS: accessFile format
 * <clientId>:<path to p12 key file> OR
 * <clientId>:<path to json key file>
 */
static int 
validate_credentials(void /*struct http_io_conf http_io*/)
{

    /* Default to $HOME/.cloudbacker for accessFile */
    if (config.http_io.ec2iam_role == NULL && config.accessFile == NULL) {
       	const char *home = getenv("HOME");
        char buf[PATH_MAX];

       	if (home != NULL) {
            snprintf(buf, sizeof(buf), "%s/%s", home, CLOUDBACKER_DEFAULT_PWD_FILE);
       	    if ((config.accessFile = strdup(buf)) == NULL)
                err(1, "strdup");
	    }
    }
    
    /* check if accessFile is valid path/file */
    if(config.accessFile != NULL) {
        struct stat sb;
        if (stat(config.accessFile, &sb) == -1) {
            warn("Invalid path or file for accessFile argument %s", config.accessFile);
            return -1;
        } 
    }

    /* If no accessId specified, default to first in accessFile */
    if (config.http_io.accessId == NULL && config.accessFile != NULL)
          search_access_for(config.accessFile, NULL, &config.http_io.accessId, NULL);
    if (config.http_io.accessId != NULL && *config.http_io.accessId == '\0')
          config.http_io.accessId = NULL;


    /* Find key in file if not specified explicitly */
    if (config.http_io.accessId == NULL && config.http_io.accessKey != NULL) {
         warnx("an `accessKey' was specified but no `accessId' was specified");
         return -1;
    }
    if (config.http_io.accessId != NULL) {
         if (config.http_io.accessKey == NULL && config.accessFile != NULL)
              search_access_for(config.accessFile, config.http_io.accessId, NULL, &config.http_io.accessKey);
         if (config.http_io.accessKey == NULL) {
              warnx("no `accessKey' specified");
              return -1;
        }
    }

   /* invokes storage specific function pointer */
   if(set_credentials() != 0)
       return -1;  

   return 0;
}

static void
dump_config(void)
{
    int i;

    (*config.log)(LOG_DEBUG, "cloudbacker config:");
    (*config.log)(LOG_DEBUG, "%24s: %s", "test mode", config.test ? "true" : "false");
    (*config.log)(LOG_DEBUG, "%24s: %s", "directIO", config.fuse_ops.direct_io ? "true" : "false");
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "accessId", config.http_io.accessId != NULL ? config.http_io.accessId : "");
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "accessKey", config.http_io.accessKey != NULL ? "****" : "");
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "accessFile", config.accessFile);
    (*config.log)(LOG_DEBUG, "%24s: %s", "accessType", config.http_io.accessType);
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "ec2iam_role", config.http_io.ec2iam_role != NULL ? config.http_io.ec2iam_role : "");
    (*config.log)(LOG_DEBUG, "%24s: %s", "authVersion", config.http_io.authVersion);
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "baseURL", config.http_io.baseURL);
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "region", config.http_io.region);
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", config.test ? "testdir" : "bucket", config.http_io.bucket);
    (*config.log)(LOG_DEBUG, "%24s: %s", "localStore", (config.localStore_io.blk_dev_path != NULL) ? config.localStore_io.blk_dev_path : "no");
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "storageClass", config.http_io.storageClass);
    (*config.log)(LOG_DEBUG, "%24s: %u keys", "maxKeys", config.http_io.maxKeys);
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "prefix", config.http_io.prefix);
    (*config.log)(LOG_DEBUG, "%24s: %s", "name hash", config.http_io.name_hash ? "yes" : "no");
    (*config.log)(LOG_DEBUG, "%24s: %s", "list_blocks", config.list_blocks_async ? "asynchronous" : (config.list_blocks ? "synchronous" : "no"));
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "mount", config.mount);
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "filename", config.fuse_ops.filename);
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "stats_filename", config.fuse_ops.stats_filename);
    (*config.log)(LOG_DEBUG, "%24s: %s (%u)", "block_size",
      config.block_size_str != NULL ? config.block_size_str : "-", config.block_size);
    (*config.log)(LOG_DEBUG, "%24s: %s (%jd)", "file_size",
      config.file_size_str != NULL ? config.file_size_str : "-", (intmax_t)config.file_size);
    (*config.log)(LOG_DEBUG, "%24s: %jd", "num_blocks", (intmax_t)config.num_blocks);
    (*config.log)(LOG_DEBUG, "%24s: 0%o", "file_mode", config.fuse_ops.file_mode);
    (*config.log)(LOG_DEBUG, "%24s: %s", "read_only", config.fuse_ops.read_only ? "true" : "false");
    (*config.log)(LOG_DEBUG, "%24s: %d", "compress", config.http_io.compress);
    (*config.log)(LOG_DEBUG, "%24s: %s (%s)", "encryption ", config.http_io.encryption != NULL ? config.http_io.encryption : "(none)", 
                                         config.http_io.cse ? "client side encryption" : "server side encryption");
    (*config.log)(LOG_DEBUG, "%24s: %u", "key_length", config.http_io.key_length);
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "password", config.http_io.password != NULL ? "****" : "");
    (*config.log)(LOG_DEBUG, "%24s: %s bps (%ju)", "max_upload",
      config.max_speed_str[HTTP_UPLOAD] != NULL ? config.max_speed_str[HTTP_UPLOAD] : "-",
      config.http_io.max_speed[HTTP_UPLOAD]);
    (*config.log)(LOG_DEBUG, "%24s: %s bps (%ju)", "max_download",
      config.max_speed_str[HTTP_DOWNLOAD] != NULL ? config.max_speed_str[HTTP_DOWNLOAD] : "-",
      config.http_io.max_speed[HTTP_DOWNLOAD]);
    (*config.log)(LOG_DEBUG, "%24s: %us", "timeout", config.http_io.timeout);
    (*config.log)(LOG_DEBUG, "%24s: %ums", "initial_retry_pause", config.http_io.initial_retry_pause);
    (*config.log)(LOG_DEBUG, "%24s: %ums", "max_retry_pause", config.http_io.max_retry_pause);
    (*config.log)(LOG_DEBUG, "%24s: %ums", "min_write_delay", config.ec_protect.min_write_delay);
    (*config.log)(LOG_DEBUG, "%24s: %ums", "md5_cache_time", config.ec_protect.cache_time);
    (*config.log)(LOG_DEBUG, "%24s: %u entries", "md5_cache_size", config.ec_protect.cache_size);
    (*config.log)(LOG_DEBUG, "%24s: %u entries", "block_cache_size", config.block_cache.cache_size);
    (*config.log)(LOG_DEBUG, "%24s: %u threads", "block_cache_threads", config.block_cache.num_threads);
    (*config.log)(LOG_DEBUG, "%24s: %ums", "block_cache_timeout", config.block_cache.timeout);
    (*config.log)(LOG_DEBUG, "%24s: %ums", "block_cache_write_delay", config.block_cache.write_delay);
    (*config.log)(LOG_DEBUG, "%24s: %u blocks", "block_cache_max_dirty", config.block_cache.max_dirty);
    (*config.log)(LOG_DEBUG, "%24s: %s", "block_cache_sync", config.block_cache.synchronous ? "true" : "false");
    (*config.log)(LOG_DEBUG, "%24s: %u blocks", "read_ahead", config.block_cache.read_ahead);
    (*config.log)(LOG_DEBUG, "%24s: %u blocks", "read_ahead_trigger", config.block_cache.read_ahead_trigger);
    (*config.log)(LOG_DEBUG, "%24s: \"%s\"", "block_cache_cache_file",
      config.block_cache.cache_file != NULL ? config.block_cache.cache_file : "");
    (*config.log)(LOG_DEBUG, "%24s: %s", "block_cache_no_verify", config.block_cache.no_verify ? "true" : "false");
    (*config.log)(LOG_DEBUG, "fuse_main arguments:");
    for (i = 0; i < config.fuse_args.argc; i++)
        (*config.log)(LOG_DEBUG, "  [%d] = \"%s\"", i, config.fuse_args.argv[i]);
}

static void
syslog_logger(int level, const char *fmt, ...)
{
    va_list args;

    /* Filter debug messages */
    if (!config.debug && level == LOG_DEBUG)
        return;

    /* Send message to syslog */
    va_start(args, fmt);
    vsyslog(level, fmt, args);
    va_end(args);
}

static void
stderr_logger(int level, const char *fmt, ...)
{
    const char *levelstr;
    char timebuf[32];
    va_list args;
    struct tm tm;
    time_t now;

    /* Filter debug messages */
    if (!config.debug && level == LOG_DEBUG)
        return;

    /* Get level descriptor */
    switch (level) {
    case LOG_ERR:
        levelstr = "ERROR";
        break;
    case LOG_WARNING:
        levelstr = "WARNING";
        break;
    case LOG_NOTICE:
        levelstr = "NOTICE";
        break;
    case LOG_INFO:
        levelstr = "INFO";
        break;
    case LOG_DEBUG:
        levelstr = "DEBUG";
        break;
    default:
        levelstr = "<?>";
        break;
    }

    /* Format and print log message */
    time(&now);
    strftime(timebuf, sizeof(timebuf), "%F %T", localtime_r(&now, &tm));
    va_start(args, fmt);
    fprintf(stderr, "%s %s: ", timebuf, levelstr);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

static void
usage(void)
{
    int i;

    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\tcloudbacker [options] bucket /mount/point\n");
    fprintf(stderr, "\tcloudbacker --test [options] directory /mount/point\n");
    fprintf(stderr, "\tcloudbacker --erase [options] bucket\n");
    fprintf(stderr, "\tcloudbacker --reset-mounted-flag [options] bucket\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t--%-27s %s\n", "accessFile=FILE", "File containing `accessID:accessKey' pairs");
    fprintf(stderr, "\t--%-27s %s\n", "accessId=ID", "GS or S3 access key ID");
    fprintf(stderr, "\t--%-27s %s\n", "accessKey=KEY", "GS secret key file path or S3 secret access key");
    fprintf(stderr, "\t--%-27s %s\n", "accessType=TYPE", "GS or S3 ACL used when creating new items; one of:");
    fprintf(stderr, "\t  %-27s ", "For GS ");
    for (i = 0; i < sizeof(gs_acls) / sizeof(*gs_acls); i++){
        if(i == 4)
           fprintf(stderr, "\n\t  %-27s "," ");
        fprintf(stderr, "%s%s", ((i > 0) && (i != 4)) ? ", " : "  ", gs_acls[i]);  
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "\t  %-27s ", "For S3 ");
    for (i = 0; i < sizeof(s3_acls) / sizeof(*s3_acls); i++)
        fprintf(stderr, "%s%s", i > 0 ? ", " : "  ", s3_acls[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t--%-27s %s\n", "authVersion=TYPE", "Specify GS or S3 authentication style; one of:");
    fprintf(stderr, "\t  %-27s ", "For GS ");
    for (i = 0; i < sizeof(gs_auth_types) / sizeof(*gs_auth_types); i++)
        fprintf(stderr, "%s%s", i > 0 ? ", " : "  ", gs_auth_types[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t  %-27s ", "For S3 ");
    for (i = 0; i < sizeof(s3_auth_types) / sizeof(*s3_auth_types); i++)
        fprintf(stderr, "%s%s", i > 0 ? ", " : "  ", s3_auth_types[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t--%-27s %s\n", "accessEC2IAM=ROLE", "Acquire S3 credentials from EC2 machine via IAM role");
    fprintf(stderr, "\t--%-27s %s\n", "baseURL=URL", "Base URL for all requests");
    fprintf(stderr, "\t--%-27s %s\n", "blockCacheFile=FILE", "Block cache persistent file");
    fprintf(stderr, "\t--%-27s %s\n", "blockCacheMaxDirty=NUM", "Block cache maximum number of dirty blocks");
    fprintf(stderr, "\t--%-27s %s\n", "blockCacheNoVerify", "Disable verification of data loaded from cache file");
    fprintf(stderr, "\t--%-27s %s\n", "blockCacheSize=NUM", "Block cache size (in number of blocks)");
    fprintf(stderr, "\t--%-27s %s\n", "blockCacheSync", "Block cache performs all writes synchronously");
    fprintf(stderr, "\t--%-27s %s\n", "blockCacheThreads=NUM", "Block cache write-back thread pool size");
    fprintf(stderr, "\t--%-27s %s\n", "blockCacheTimeout=MILLIS", "Block cache entry timeout (zero = infinite)");
    fprintf(stderr, "\t--%-27s %s\n", "blockCacheWriteDelay=MILLIS", "Block cache maximum write-back delay");
    fprintf(stderr, "\t--%-27s %s\n", "blockSize=SIZE", "Block size (with optional suffix 'K', 'M', 'G', etc.)");
    fprintf(stderr, "\t--%-27s %s\n", "cacert=FILE", "Specify SSL certificate authority file");
    fprintf(stderr, "\t--%-27s %s\n", "compress[=LEVEL]", "Enable block compression, with 1=fast up to 9=small");
    fprintf(stderr, "\t--%-27s %s\n", "debug", "Enable logging of debug messages");
    fprintf(stderr, "\t--%-27s %s\n", "debug-http", "Print HTTP headers to standard output");
    fprintf(stderr, "\t--%-27s %s\n", "directIO", "Disable kernel caching of the backed file");
    fprintf(stderr, "\t--%-27s %s\n", "encrypt[=CIPHER]", "Enable encryption (implies `--compress')");
    fprintf(stderr, "\t--%-27s %s\n", "erase", "Erase all blocks in the filesystem");
    fprintf(stderr, "\t--%-27s %s\n", "fileMode=MODE", "Permissions of backed file in filesystem");
    fprintf(stderr, "\t--%-27s %s\n", "filename=NAME", "Name of backed file in filesystem");
    fprintf(stderr, "\t--%-27s %s\n", "force", "Ignore different auto-detected block and file sizes");
    fprintf(stderr, "\t--%-27s %s\n", "help", "Show this information and exit");
    fprintf(stderr, "\t--%-27s %s\n", "initialRetryPause=MILLIS", "Inital retry pause after stale data or server error");
    fprintf(stderr, "\t--%-27s %s\n", "insecure", "Don't verify SSL server identity");
    fprintf(stderr, "\t--%-27s %s\n", "keyLength", "Override generated cipher key length");
    fprintf(stderr, "\t--%-27s %s\n", "localStore=/blk/dev/path", "Enable local storage with block device path");
    fprintf(stderr, "\t--%-27s %s\n", "listBlocks", "Auto-detect non-empty blocks at startup");
    fprintf(stderr, "\t--%-27s %s\n", "listBlocksAsync", "Auto-detect non-empty blocks asynchronously");
    fprintf(stderr, "\t--%-27s %s\n", "maxDownloadSpeed=BITSPERSEC", "Max download bandwith for a single read");
    fprintf(stderr, "\t--%-27s %s\n", "maxRetryPause=MILLIS", "Max total pause after stale data or server error");
    fprintf(stderr, "\t--%-27s %s\n", "maxUploadSpeed=BITSPERSEC", "Max upload bandwith for a single write");
    fprintf(stderr, "\t--%-27s %s\n", "md5CacheSize=NUM", "Max size of MD5 cache (zero = disabled)");
    fprintf(stderr, "\t--%-27s %s\n", "md5CacheTime=MILLIS", "Expire time for MD5 cache (zero = infinite)");
    fprintf(stderr, "\t--%-27s %s\n", "minWriteDelay=MILLIS", "Minimum time between same block writes");
    fprintf(stderr, "\t--%-27s %s\n", "password=PASSWORD", "Encrypt using PASSWORD");
    fprintf(stderr, "\t--%-27s %s\n", "passwordFile=FILE", "Encrypt using password read from FILE");
    fprintf(stderr, "\t--%-27s %s\n", "maxKeys=NUM", "Max blocks to be listed at a time");
    fprintf(stderr, "\t--%-27s %s\n", "prefix=STRING", "Prefix for resource names within bucket");
    fprintf(stderr, "\t--%-27s %s\n", "quiet", "Omit progress output at startup");
    fprintf(stderr, "\t--%-27s %s\n", "readAhead=NUM", "Number of blocks to read-ahead");
    fprintf(stderr, "\t--%-27s %s\n", "readAheadTrigger=NUM", "# of sequentially read blocks to trigger read-ahead");    
    fprintf(stderr, "\t--%-27s %s\n", "nameHash", "Enables name hashing for objects");
    fprintf(stderr, "\t--%-27s %s\n", "readOnly", "Return `Read-only file system' error for write attempts");
    fprintf(stderr, "\t--%-27s %s\n", "region=region", "Specify AWS region");
    fprintf(stderr, "\t--%-27s %s\n", "reset-mounted-flag", "Reset `already mounted' flag in the filesystem");
    fprintf(stderr, "\t--%-27s %s\n", "storageClass=class", "GS or S3 storage class used when mounting file system; one of:");
    fprintf(stderr, "\t  %-27s ", "For GS ");
    for (i = 0; i < sizeof(gs_storageClasses) / sizeof(*gs_storageClasses); i++)
        fprintf(stderr, "%s%s", i > 0 ? ", " : "  ", gs_storageClasses[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t  %-27s ", "For S3 ");
    for (i = 0; i < sizeof(s3_storageClasses) / sizeof(*s3_storageClasses); i++)
        fprintf(stderr, "%s%s", i > 0 ? ", " : "  ", s3_storageClasses[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t--%-27s %s\n", "size=SIZE", "File size (with optional suffix 'K', 'M', 'G', etc.)");
    fprintf(stderr, "\t--%-27s %s\n", "cse", "Enable client side encryption");
    fprintf(stderr, "\t--%-27s %s\n", "sse", "Enable server side encryption");
    fprintf(stderr, "\t--%-27s %s\n", "ssl", "Enable SSL");
    fprintf(stderr, "\t--%-27s %s\n", "statsFilename=NAME", "Name of statistics file in filesystem");
    fprintf(stderr, "\t--%-27s %s\n", "test", "Run in local test mode (bucket is a directory)");
    fprintf(stderr, "\t--%-27s %s\n", "timeout=SECONDS", "Max time allowed for one HTTP operation");
    fprintf(stderr, "\t--%-27s %s\n", "timeout=SECONDS", "Specify HTTP operation timeout");
    fprintf(stderr, "\t--%-27s %s\n", "version", "Show version information and exit");
    fprintf(stderr, "\t--%-27s %s\n", "vhost", "Use virtual host bucket style URL for all requests");
    fprintf(stderr, "Default values:\n");
    fprintf(stderr, "\t--%-27s \"%s\"\n", "accessFile", "$HOME/" CLOUDBACKER_DEFAULT_PWD_FILE);
    fprintf(stderr, "\t--%-27s %s\n", "accessId", "The first one listed in `accessFile'");
    fprintf(stderr, "\t--%-27s %s\"%s\"%s\"%s\"\n", "accessType","For GS ", GSBACKER_DEFAULT_ACCESS_TYPE, ", For S3 ",S3BACKER_DEFAULT_ACCESS_TYPE );
    fprintf(stderr, "\t--%-27s %s\"%s\"%s\"%s\"\n", "authVersion","For GS ", GSBACKER_DEFAULT_AUTH_VERSION, ", For S3 ",S3BACKER_DEFAULT_AUTH_VERSION);
    fprintf(stderr, "\t--%-27s %s\"%s\"%s\"%s\"\n", "baseURL","For GS ", "http://" GS_DOMAIN "/" , ", For S3 ","http://s3." S3_DOMAIN "/");
    fprintf(stderr, "\t--%-27s %u\n", "blockCacheSize", CLOUDBACKER_DEFAULT_BLOCK_CACHE_SIZE);
    fprintf(stderr, "\t--%-27s %u\n", "blockCacheThreads", CLOUDBACKER_DEFAULT_BLOCK_CACHE_NUM_THREADS);
    fprintf(stderr, "\t--%-27s %u\n", "blockCacheTimeout", CLOUDBACKER_DEFAULT_BLOCK_CACHE_TIMEOUT);
    fprintf(stderr, "\t--%-27s %u\n", "blockCacheWriteDelay", CLOUDBACKER_DEFAULT_BLOCK_CACHE_WRITE_DELAY);
    fprintf(stderr, "\t--%-27s %d\n", "blockSize", CLOUDBACKER_DEFAULT_BLOCKSIZE);
    fprintf(stderr, "\t--%-27s \"%s\"\n", "filename", CLOUDBACKER_DEFAULT_FILENAME);
    fprintf(stderr, "\t--%-27s %u\n", "initialRetryPause", CLOUDBACKER_DEFAULT_INITIAL_RETRY_PAUSE);
    fprintf(stderr, "\t--%-27s %u\n", "md5CacheSize", CLOUDBACKER_DEFAULT_MD5_CACHE_SIZE);
    fprintf(stderr, "\t--%-27s %u\n", "md5CacheTime", CLOUDBACKER_DEFAULT_MD5_CACHE_TIME);
    fprintf(stderr, "\t--%-27s 0%03o (0%03o if `--readOnly')\n", "fileMode",
      CLOUDBACKER_DEFAULT_FILE_MODE, CLOUDBACKER_DEFAULT_FILE_MODE_READ_ONLY);
    fprintf(stderr, "\t--%-27s %u\n", "maxRetryPause", CLOUDBACKER_DEFAULT_MAX_RETRY_PAUSE);
    fprintf(stderr, "\t--%-27s %u\n", "minWriteDelay", CLOUDBACKER_DEFAULT_MIN_WRITE_DELAY);
    fprintf(stderr, "\t--%-27s %u\n", "maxKeys", LIST_BLOCKS_CHUNK);
    fprintf(stderr, "\t--%-27s \"%s\"\n", "prefix", CLOUDBACKER_DEFAULT_PREFIX);
    fprintf(stderr, "\t--%-27s %u\n", "readAhead", CLOUDBACKER_DEFAULT_READ_AHEAD);
    fprintf(stderr, "\t--%-27s %u\n", "readAheadTrigger", CLOUDBACKER_DEFAULT_READ_AHEAD_TRIGGER);
    fprintf(stderr, "\t--%-27s \"%s\"\n", "region", S3BACKER_DEFAULT_REGION);
    fprintf(stderr, "\t--%-27s \"%s\"\n", "statsFilename", CLOUDBACKER_DEFAULT_STATS_FILENAME);
    fprintf(stderr, "\t--%-27s %u\n", "timeout", CLOUDBACKER_DEFAULT_TIMEOUT);
    fprintf(stderr, "FUSE options (partial list):\n");
    fprintf(stderr, "\t%-29s %s\n", "-o nonempty", "Allows mount over a non-empty directory");
    fprintf(stderr, "\t%-29s %s\n", "-o uid=UID", "Set user ID");
    fprintf(stderr, "\t%-29s %s\n", "-o gid=GID", "Set group ID");
    fprintf(stderr, "\t%-29s %s\n", "-o sync_read", "Do synchronous reads");
    fprintf(stderr, "\t%-29s %s\n", "-o max_readahead=NUM", "Set maximum read-ahead (bytes)");
    fprintf(stderr, "\t%-29s %s\n", "-f", "Run in the foreground (do not fork)");
    fprintf(stderr, "\t%-29s %s\n", "-d", "Debug mode (implies -f)");
    fprintf(stderr, "\t%-29s %s\n", "-s", "Run in single-threaded mode");
}

/* GS specific validation functions invoked through function pointers for parsing command line arguments */	 
/*
 * cloudbacker accessFile format
 *
 * For GCS: accessFile format
 * <clientId>:<path to p12 key file> OR
 * <clientId>:<path to json key file>
 */
int
validate_gs_credentials(void)
{
    const int customBaseURL = config.http_io.baseURL != NULL;

    /* If no accessId, only read operations will succeed */
    if (config.http_io.accessId == NULL && !config.fuse_ops.read_only && !customBaseURL){
        warnx("warning: no `accessId' specified; only read operations will succeed");
        warnx("you can eliminate this warning by providing the `--readOnly' flag");
    }
    
    /* Check for conflict between explicit GS and EC2 IAM role */
    if (config.http_io.accessId != NULL && config.http_io.ec2iam_role != NULL) {
          warnx("An `accessEC2IAM' role is not compatible with GS. Ignoring `accessEC2IAM' flag. ");
          config.http_io.ec2iam_role = NULL;
    }

    if(config.http_io.accessId != NULL)
        config.http_io.auth.u.gs.clientId = strdup(config.http_io.accessId);
    
    if(config.http_io.accessKey != NULL) {
        config.http_io.auth.u.gs.secret_keyfile = strdup(config.http_io.accessKey);
    
        struct stat sb;
        if (stat(config.http_io.auth.u.gs.secret_keyfile, &sb) == -1) {
            warn("Invalid path to secret key file %s", config.http_io.auth.u.gs.secret_keyfile);
            return -1;
        }
    }

    return 0;
}

/* For google storage valid authentication versions are oAuth2.0 and AWS2(supports in backward compatibility mode). */
int validate_gs_authVersion(void)
{
    int i = 0;
    char auth_buf[8];
    if(config.http_io.authVersion != NULL){
        for (i = 0; i < sizeof(gs_auth_types) / sizeof(*gs_auth_types); i++) {
            if (strcasecmp(config.http_io.authVersion, gs_auth_types[i]) == 0)
                break;
        }
        if (i == sizeof(gs_auth_types) / sizeof(*gs_auth_types)) {
            warnx("illegal authentication version `%s'", config.http_io.authVersion);
            return -1;
        }
        config.http_io.auth.u.gs.authVersion = strdup(config.http_io.authVersion);
    }
    else{
        strcpy(auth_buf, GSBACKER_DEFAULT_AUTH_VERSION);
        config.http_io.auth.u.gs.authVersion = strdup(auth_buf);
    }
    return 0;
}

int validate_gs_accessType(void)
{
    int i = 0;
    if(config.http_io.accessType != NULL){
        for (i = 0; i < sizeof(gs_acls) / sizeof(*gs_acls); i++) {
            if (strcmp(config.http_io.accessType, gs_acls[i]) == 0)
                break;
        }
        if (i == sizeof(gs_acls) / sizeof(*gs_acls)) {
            warnx("illegal access type `%s'", config.http_io.accessType);
            return -1;
        }
        config.http_io.auth.u.gs.accessType = strdup(config.http_io.accessType);
    }
    else{
        config.http_io.auth.u.gs.accessType = GSBACKER_DEFAULT_ACCESS_TYPE;
    }
    return 0;
}
/*
 * validate storage class.
 * default storage class for GS is nearline
 * GS supports Standard Storage, Cloud Storage Nearline and Durable Reduced Availability (DRA) storage classes
 * In GS, storage class is bucket specific. All objects in a bucket are of same storage class as of bucket.
 */
int validate_gs_storageClass(void)
{
    if(config.http_io.storageClass != NULL){
        int i = 0;
        for (i = 0; i < sizeof(gs_storageClasses) / sizeof(*gs_storageClasses); i++) {
            if (strcasecmp(config.http_io.storageClass, gs_storageClasses[i]) == 0)
                break;
        }
        if (i == sizeof(gs_storageClasses) / sizeof(*gs_storageClasses)) {
            warnx("illegal storageClass type `%s' for google storage bucket", config.http_io.storageClass);
            return -1;
        }
    }
    else {
        config.http_io.storageClass = SCLASS_GS_NEARLINE;
    }

    return 0;
}

/* sets url buf */
int set_gs_urlbuf(void)
{
    char urlbuf[512];
    snprintf(urlbuf, sizeof(urlbuf), "http%s://%s/", config.ssl ? "s" : "", GS_DOMAIN);
    if ((config.http_io.baseURL = strdup(urlbuf)) == NULL) {
        warn("malloc");
        return -1;
    }
    return 0;
}

/* S3 specific validation functions invoked through function pointers for parsing command line arguments */	 
/*
 * Function to read credentials from accessFile or command line arguments accessId and accesskey
 *
 * cloudbacker accessFile format
 *
 * For s3: accessFile format
 * <accessId>:<secret oraccesskey>
 */
int
validate_s3_credentials(void)
{
    const int customBaseURL = config.http_io.baseURL != NULL;
    
    /* If no accessId, only read operations will succeed */
    if (config.http_io.accessId == NULL && !config.fuse_ops.read_only && !customBaseURL){
        if(config.http_io.ec2iam_role == NULL ) {
            warnx("warning: no `accessId' specified; only read operations will succeed");
            warnx("you can eliminate this warning by providing the `--readOnly' flag");
        }
    }

    /* Check for conflict between explicit accessId and EC2 IAM role */
    if (config.http_io.accessId != NULL && config.http_io.ec2iam_role != NULL) {
        warnx("an `accessId' must not be specified when an `accessEC2IAM' role is specified");
        return -1;
    }

    if(config.http_io.accessId != NULL && config.http_io.accessKey != NULL) {
        config.http_io.auth.u.s3.accessId = strdup(config.http_io.accessId);
        config.http_io.auth.u.s3.accessKey = strdup(config.http_io.accessKey);
    }
    if(config.http_io.ec2iam_role != NULL)
        config.http_io.auth.u.s3.ec2iam_role = strdup(config.http_io.ec2iam_role);
    else
        config.http_io.auth.u.s3.ec2iam_role = NULL;

    return 0;
}

/*
 * For google storage valid authentication versions are oAuth2.0 and AWS2.
 * For amazon s3 storage valid authentication versions are AWS2 and AWS4.
 */

int validate_s3_authVersion(void)
{
    int i = 0;
    char auth_buf[8];
    if(config.http_io.authVersion != NULL){
        for (i = 0; i < sizeof(s3_auth_types) / sizeof(*s3_auth_types); i++) {
            if (strcasecmp(config.http_io.authVersion, s3_auth_types[i]) == 0)
                break;
        }
        if (i == sizeof(s3_auth_types) / sizeof(*s3_auth_types)) {
            warnx("illegal authentication version `%s'", config.http_io.authVersion);
            return -1;
        }
        config.http_io.auth.u.s3.authVersion = strdup(config.http_io.authVersion);
    }
    else{
        strcpy(auth_buf, S3BACKER_DEFAULT_AUTH_VERSION);
        config.http_io.auth.u.s3.authVersion = strdup(auth_buf);
    }
    return 0;
}

int validate_s3_accessType(void)
{
    int i = 0;
    if(config.http_io.accessType != NULL){
        for (i = 0; i < sizeof(s3_acls) / sizeof(*s3_acls); i++) {
            if (strcmp(config.http_io.accessType, s3_acls[i]) == 0)
                break;
        }
        if (i == sizeof(s3_acls) / sizeof(*s3_acls)) {
            warnx("illegal access type `%s'", config.http_io.accessType);
            return -1;
        }
        config.http_io.auth.u.s3.accessType = strdup(config.http_io.accessType);
    }
    else{
        config.http_io.auth.u.s3.accessType = S3BACKER_DEFAULT_ACCESS_TYPE;
    }
    return 0;
}

/*
 * validate storage class.
 * default storage class for S3 is standard
 * S3 supports Standard storage and Reduced Redundancy storage (RRS) storage classes.
 * In S3, storage class is object specific.
 */
int validate_s3_storageClass(void)
{
    if(config.http_io.storageClass != NULL){
        int i = 0;
        for (i = 0; i < sizeof(s3_storageClasses) / sizeof(*s3_storageClasses); i++) {
            if (strcasecmp(config.http_io.storageClass, s3_storageClasses[i]) == 0)
                break;
        }
        if (i == sizeof(s3_storageClasses) / sizeof(*s3_storageClasses)) {
            warnx("illegal storageClass type `%s' for s3 storage bucket", config.http_io.storageClass);
            return -1;
        }
    }
    else {
        config.http_io.storageClass = SCLASS_STANDARD;
    }

    return 0;
}

/* set url buf based on region */
int set_s3_urlbuf(void)
{
    const int customRegion = config.http_io.region != NULL;
    char urlbuf[512];
    if (customRegion && strcmp(config.http_io.region, S3BACKER_DEFAULT_REGION) != 0)
        snprintf(urlbuf, sizeof(urlbuf), "http%s://s3-%s.%s/", (config.ssl || config.http_io.sse) ? "s" : "", config.http_io.region, S3_DOMAIN);
    else
        snprintf(urlbuf, sizeof(urlbuf), "http%s://s3.%s/", (config.ssl || config.http_io.sse) ? "s" : "", S3_DOMAIN);

    if ((config.http_io.baseURL = strdup(urlbuf)) == NULL) {
        warn("malloc");
        return -1;
    }
    return 0;
}
