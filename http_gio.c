
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
#include "block_part.h"
#include "http_gio.h"
#include "gsb_http_io.h"
#include "s3b_http_io.h"

/* cloudbacker_store functions */
static int http_io_meta_data(struct cloudbacker_store *cb);
static int http_io_set_mounted(struct cloudbacker_store *cb, int *old_valuep, int new_value);
static int http_io_read_block(struct cloudbacker_store *cb, cb_block_t block_num, void *dest,
  u_char *actual_md5, const u_char *expect_md5, int strict);
static int http_io_write_block(struct cloudbacker_store *cb, cb_block_t block_num, const void *src, u_char *md5,
  check_cancel_t *check_cancel, void *check_cancel_arg);
static int http_io_set_meta_data(struct cloudbacker_store *cb, int operation);
static int http_io_read_block_part(struct cloudbacker_store *cb, cb_block_t block_num, u_int off, u_int len, void *dest);
static int http_io_write_block_part(struct cloudbacker_store *cb, cb_block_t block_num, u_int off, u_int len, const void *src);
static int http_io_list_blocks(struct cloudbacker_store *cb, block_list_func_t *callback, void *arg);
static int http_io_flush(struct cloudbacker_store *cb);
static void http_io_destroy(struct cloudbacker_store *cb);
static int http_io_set(struct cloudbacker_store *cb, int mounted);
/* Misc */
static void http_io_openssl_locker(int mode, int i, const char *file, int line);
static u_long http_io_openssl_ider(void);
static void http_io_init(struct http_io_private *priv);

/* Internal variables */
static pthread_mutex_t *openssl_locks;
static int num_openssl_locks;
static u_char zero_md5[MD5_DIGEST_LENGTH];
static u_char zero_hmac[SHA_DIGEST_LENGTH];


/* NULL-terminated vector of header parsers */
header_parser_t cb_header_parser[] = {
    file_size_parser, block_size_parser, name_hash_parser,
    compression_parser, encryption_parser, encryption_cipher_parser, etag_parser, 
    hmac_parser, encoding_parser, NULL
};


/*
 * Async block list support
 */
struct http_list_blocks_arg {
    struct cloudbacker_store    *cb;
    struct http_io_private	*priv;
};

void
http_list_blocks_callback(void *arg, cb_block_t block_num)
{
    struct http_list_blocks *const lb = arg;
    const int bits_per_word = sizeof(*lb->bitmap) * 8;
    int print_dot = 0;

    if (lb->async)
        pthread_mutex_lock(lb->mutex);
    lb->bitmap[block_num / bits_per_word] |= 1 << (block_num % bits_per_word);
    lb->count++;
    if (lb->print_dots && (lb->count % BLOCKS_PER_DOT) == 0)
	print_dot = 1;
    if (lb->async)
        pthread_mutex_unlock(lb->mutex);
    if (print_dot) {
        fprintf(stderr, ".");
        fflush(stderr);
    }
}

static void *
http_list_blocks_main(void *param)
{
    struct http_list_blocks_arg *arg = param;
    struct http_io_private 	*const priv = arg->priv;
    int r = 0;
    struct http_list_blocks lb;

    lb.bitmap = priv->non_zero;
    lb.print_dots = 0;
    lb.count = 0;
    lb.mutex = &priv->mutex;
    lb.async = 1;

    (*priv->config->log)(LOG_INFO, "http_list_blocks_main(): started asynchronous listing of blocks");

    if ((r = (arg->cb->list_blocks)(arg->cb, http_list_blocks_callback, &lb)) != 0) {
        free(param);
        err(1, "can't list blocks: %s", strerror(r));
    }

    pthread_mutex_lock(&priv->mutex);
    priv->non_zero_complete = HTTP_IO_BITMAP_DONE;
    pthread_mutex_unlock(&priv->mutex);

    (*priv->config->log)(LOG_INFO, "http_list_blocks_main(): finished asynchronous listing of blocks");
    (*priv->config->log)(LOG_INFO, "http_list_blocks_main(): %ju non-zero blocks found", lb.count);

    free(param);

    return NULL;
}


/*
 * Constructor
 *
 * On error, returns NULL and sets `errno'.
 */
struct cloudbacker_store *
http_io_create(struct http_io_conf *config)
{
    struct cloudbacker_store *cb;
    struct http_io_private *priv;
    struct curl_holder *holder;
    int nlocks;
    int r;

    /* Sanity check: we can really only handle one instance */
    if (openssl_locks != NULL) {
        (*config->log)(LOG_ERR, "http_io_create() called twice");
        r = EALREADY;
        goto fail0;
    }

    /* Initialize structures */
    if ((cb = calloc(1, sizeof(*cb))) == NULL) {
        r = errno;
        goto fail0;
    }
    
    if ((priv = calloc(1, sizeof(*priv))) == NULL) {
        r = errno;
        goto fail1;
    }
    priv->config = config;

    /* Allocate memory for http IO parameters structure*/
    if ((priv->config->http_io_params = calloc(1, sizeof(*(priv->config->http_io_params)))) == NULL) {
        r = errno;
        goto fail2;
    }
   
    /* generic functions */ 
    cb->meta_data = http_io_meta_data;
    cb->set_mounted = http_io_set_mounted;
    cb->set_meta_data = http_io_set_meta_data;
    cb->read_block = http_io_read_block;
    cb->write_block = http_io_write_block;
    cb->read_block_part = http_io_read_block_part;
    cb->write_block_part = http_io_write_block_part;
    cb->list_blocks = http_io_list_blocks;
    cb->flush = http_io_flush;
    cb->destroy = http_io_destroy;
    cb->init = http_io_set;

    /* initialize storage specific function pointers */
    if(config->storage_prefix == GS_STORAGE){
    
       /* set http IO request parameters */
       config->set_http_io_params = set_http_io_gsb_params;   

       /* get bucket storageClass attribute */
       cb->bucket_attributes = http_io_gcs_bucket_attributes;

       /* gcs oAuth 2.0 version */
       if ( (config->auth.u.gs.clientId != NULL) && (strcasecmp(config->auth.u.gs.authVersion, AUTH_VERSION_OAUTH2) == 0) )
           config->authenticate = http_io_add_oAuth2;
       
       /* update authentication threads */
       config->update_auth_threads = update_gcs_credentials;
       
       /* destroy */
       config->destroy_auth_threads = http_io_gcs_destroy;       
    }
    else if (config->storage_prefix == S3_STORAGE) {
     
       /* set http IO request parameters */
       config->set_http_io_params = set_http_io_s3b_params;
        
       /* Will do nothing for s3b - just dummy as of now */
       cb->bucket_attributes = http_io_s3b_bucket_attributes;     

       /* Which auth version? */
       if (strcasecmp(config->auth.u.s3.authVersion, AUTH_VERSION_AWS2) == 0)
           config->authenticate = http_io_add_auth2;
       else if (strcasecmp(config->auth.u.s3.authVersion, AUTH_VERSION_AWS4) == 0)
           config->authenticate = http_io_add_auth4;        
       
       /* update EC2 IAM role authentication threads */
       config->update_auth_threads = update_iam_credentials;
       
       /* destroy */
       config->destroy_auth_threads = http_io_s3_destroy;
    }

    /* initialize http layer parameters */
    http_io_init(priv);
    
    if ((r = pthread_mutex_init(&priv->mutex, NULL)) != 0)
        goto fail2;
    LIST_INIT(&priv->curls);
    cb->data = priv;

    /* Initialize openssl */
    num_openssl_locks = CRYPTO_num_locks();
    if ((openssl_locks = malloc(num_openssl_locks * sizeof(*openssl_locks))) == NULL) {
        r = errno;
        goto fail3;
    }
    for (nlocks = 0; nlocks < num_openssl_locks; nlocks++) {
        if ((r = pthread_mutex_init(&openssl_locks[nlocks], NULL)) != 0)
            goto fail4;
    }
    CRYPTO_set_locking_callback(http_io_openssl_locker);
    CRYPTO_set_id_callback(http_io_openssl_ider);

    /* Initialize encryption */
    if (config->encryption != NULL) {
        char saltbuf[strlen(config->bucket) + 1 + strlen(config->prefix) + 1];
        u_int cipher_key_len;

        /* Sanity checks */
        assert(config->password != NULL);
        assert(config->block_size % EVP_MAX_IV_LENGTH == 0);

        /* Find encryption algorithm */
        OpenSSL_add_all_ciphers();
        if ((priv->cipher = EVP_get_cipherbyname(config->encryption)) == NULL) {
            (*config->log)(LOG_ERR, "unknown encryption cipher `%s'", config->encryption);
            r = EINVAL;
            goto fail4;
        }
        if (EVP_CIPHER_block_size(priv->cipher) != EVP_CIPHER_iv_length(priv->cipher)) {
            (*config->log)(LOG_ERR, "invalid encryption cipher `%s': block size %d != IV length %d",
              config->encryption, EVP_CIPHER_block_size(priv->cipher), EVP_CIPHER_iv_length(priv->cipher));
            r = EINVAL;
            goto fail4;
        }
        cipher_key_len = EVP_CIPHER_key_length(priv->cipher);
        priv->keylen = config->key_length > 0 ? config->key_length : cipher_key_len;
        if (priv->keylen < cipher_key_len || priv->keylen > sizeof(priv->key)) {
            (*config->log)(LOG_ERR, "key length %u for cipher `%s' is out of range", priv->keylen, config->encryption);
            r = EINVAL;
            goto fail4;
        }

        /* Hash password to get bulk data encryption key */
        snprintf(saltbuf, sizeof(saltbuf), "%s/%s", config->bucket, config->prefix);
        if ((r = PKCS5_PBKDF2_HMAC_SHA1(config->password, strlen(config->password),
          (u_char *)saltbuf, strlen(saltbuf), PBKDF2_ITERATIONS, priv->keylen, priv->key)) != 1) {
            (*config->log)(LOG_ERR, "failed to create encryption key");
            r = EINVAL;
            goto fail4;
        }
        /* Hash the bulk encryption key to get the IV encryption key */
        if ((r = PKCS5_PBKDF2_HMAC_SHA1((char *)priv->key, priv->keylen,
          priv->key, priv->keylen, PBKDF2_ITERATIONS, priv->keylen, priv->ivkey)) != 1) {
            (*config->log)(LOG_ERR, "failed to create encryption key");
            r = EINVAL;
            goto fail4;
        }

        /* Encryption debug */
#if DEBUG_ENCRYPTION
    {
        char keybuf[priv->keylen * 2 + 1];
        char ivkeybuf[priv->keylen * 2 + 1];
        http_io_prhex(keybuf, priv->key, priv->keylen);
        http_io_prhex(ivkeybuf, priv->ivkey, priv->keylen);
        (*config->log)(LOG_DEBUG, "ENCRYPTION INIT: cipher=\"%s\" pass=\"%s\" salt=\"%s\" key=0x%s ivkey=0x%s", config->encryption, config->password, saltbuf, keybuf, ivkeybuf);
    }
#endif
    }

    /* Initialize cURL */
    curl_global_init(CURL_GLOBAL_ALL);

    /* Initialize authentication credentials and start updater thread */
    if( (r = update_credentials(priv)) != 0){
        (*config->log)(LOG_ERR, "failed to update credentials thread : %s", strerror(r));
        goto fail5;
    }
    if ((r = pthread_create(&priv->auth_thread, NULL, update_credentials_main, priv)) != 0){
        (*config->log)(LOG_ERR, "failed to create authentication thread: %s", strerror(r));
        goto fail5; 
    } 
    
    /* Take ownership of non-zero block bitmap */
    priv->non_zero = config->nonzero_bitmap;
    priv->non_zero_complete = config->nonzero_bitmap_complete;
    config->nonzero_bitmap = NULL;

    priv->block_list_thread = (pthread_t)0;
    if (priv->non_zero_complete == HTTP_IO_BITMAP_ASYNC) {
        struct http_list_blocks_arg *param =
            malloc(sizeof(struct http_list_blocks_arg));
        if (param == NULL) {
            r = ENOMEM;
            goto fail5;
        }
        param->priv = priv;
        param->cb = cb;

        /* Start asyncronous block listing to populate the non-zero bitmap */
        if ((r = pthread_create(&priv->block_list_thread, NULL, http_list_blocks_main, param)) != 0){
            (*config->log)(LOG_ERR, "failed to asynchronous list blocks thread: %s", strerror(r));
            goto fail5;
        }
    }

    /* Done */
    return cb;

fail5:
    while ((holder = LIST_FIRST(&priv->curls)) != NULL) {
        curl_easy_cleanup(holder->curl);
        LIST_REMOVE(holder, link);
        free(holder);
    }
    curl_global_cleanup();
fail4:
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    while (nlocks > 0)
        pthread_mutex_destroy(&openssl_locks[--nlocks]);
    free(openssl_locks);
    openssl_locks = NULL;
    num_openssl_locks = 0;
fail3:
    pthread_mutex_destroy(&priv->mutex);
fail2:
    free(priv);
fail1:
    free(cb);
fail0:
    (*config->log)(LOG_ERR, "http_io creation failed: %s", strerror(r));
    errno = r;
    return NULL;
}

/*
 * Destructor
 */
static void
http_io_destroy(struct cloudbacker_store *const cb)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;
    struct curl_holder *holder;
    int r = 0;

    /* Shut down authenication thread */
    priv->shutting_down = 1;
    (*config->destroy_auth_threads)(priv);

    /* Shut down asynchronous block listing thread if any */
    if (priv->non_zero_complete != HTTP_IO_BITMAP_NONE &&
	priv->block_list_thread) {
	(*config->log)(LOG_DEBUG, "waiting for async list blocks thread to shutdown");
	if ((r = pthread_cancel(priv->block_list_thread)) != 0)
	    (*config->log)(LOG_WARNING, "pthread_cancel: %s", strerror(r));
	if ((r = pthread_join(priv->block_list_thread, NULL)) != 0)
	    (*config->log)(LOG_ERR, "pthread_join: %s", strerror(r));
	else
	    (*config->log)(LOG_DEBUG, "Async block listing thread successfully shutdown");
    }

    /* Clean up openssl */
    while (num_openssl_locks > 0)
        pthread_mutex_destroy(&openssl_locks[--num_openssl_locks]);
    free(openssl_locks);
    openssl_locks = NULL;
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    /* Clean up cURL */
    while ((holder = LIST_FIRST(&priv->curls)) != NULL) {
        curl_easy_cleanup(holder->curl);
        LIST_REMOVE(holder, link);
        free(holder);
    }
    curl_global_cleanup();

    /* Free structures */
    pthread_mutex_destroy(&priv->mutex);
    free(priv->non_zero);
    free(priv);
    free(cb);
}

static int
http_io_flush(struct cloudbacker_store *const cb)
{
    return 0;
}

static int
http_io_set(struct cloudbacker_store *cb, int mounted)
{
    return 0;
}
void
http_io_get_stats(struct cloudbacker_store *cb, struct http_io_stats *stats)
{
    struct http_io_private *const priv = cb->data;

    pthread_mutex_lock(&priv->mutex);
    memcpy(stats, &priv->stats, sizeof(*stats));
    pthread_mutex_unlock(&priv->mutex);
}


/*
 * Add date header based on supplied time.
 */
void
http_io_add_date(struct http_io_private *const priv, struct http_io *const io, time_t now)
{
    char buf[DATE_BUF_SIZE];
    struct tm tm;

    strftime(buf, sizeof(buf), priv->config->http_io_params->date_buf_fmt, gmtime_r(&now, &tm));
    io->headers = http_io_add_header(io->headers, "%s: %s", priv->config->http_io_params->date_header, buf);
}    

/*
 * Improve name hashing by reversing the bit sequence of the block number.
 *
 * Using this approach results in creating two different name spaces for the
 * object names - one 'logical', where object name is a string representation
 * of the corresponding block number, and one 'on the wire', where the name
 * is a string representation of the bit-reversed block number.
 *
 * The 'logical' names are used internally by cloudbacker, and the names are
 * conversted to the 'on the wire' representation when placed in the HTTP
 * requests. Similarly, the object names that are parsed out from the bucket
 * list reply need to be converted to the 'logical' names before acted upon,
 * and the markers for the list functions need to be converted to the 'on the
 * wire' format for the iterative list operations to perform properly.
 */
static cb_block_t bit_reverse(cb_block_t block_num)
{
  /*  int nbits = sizeof(cb_block_t) * 8;
    cb_block_t reversed_block_num = (cb_block_t)0;
    int b, ib;

    if (block_num == 0) return block_num;

    for (b = nbits - 1, ib = 0; b >= 0; b--, ib++) {
        unsigned char bit = (block_num & (1 << b)) >> b;
        reversed_block_num |= bit << ib;
    }

    return reversed_block_num;
  */

    int nbits = sizeof(cb_block_t) * 8;
    cb_block_t mask = ~UINT64_C(0);

    if (block_num == 0) return block_num;
    cb_block_t reversed_block_num = block_num;
    while ((nbits >>= 1) > 0) {
       mask ^= (mask << nbits);
       reversed_block_num = ((reversed_block_num >> nbits) & mask) | ((reversed_block_num << nbits) & ~mask);
    }

    return reversed_block_num;
}

static int
http_io_list_blocks(struct cloudbacker_store *cb, block_list_func_t *callback, void *arg)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;
    char marker[sizeof("&marker=") + strlen(config->prefix) + CB_BLOCK_NUM_DIGITS + 1];
    char urlbuf[URL_BUF_SIZE(config) + sizeof(marker) + 32];
    struct http_io io;
    int r;

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = cb_header_parser;
    io.url = urlbuf;
    io.method = HTTP_GET;
    io.config = config;
    io.xml_error = XML_ERROR_NONE;
    io.callback_func = callback;
    io.callback_arg = arg;

    /* Create XML parser */
    if ((io.xml = XML_ParserCreate(NULL)) == NULL) {
        (*config->log)(LOG_ERR, "failed to create XML parser");
        return ENOMEM;
    }

    /* Allocate buffers for XML path and tag text content */
    io.xml_text_max = strlen(config->prefix) + CB_BLOCK_NUM_DIGITS + 10;
    if ((io.xml_text = malloc(io.xml_text_max + 1)) == NULL) {
        (*config->log)(LOG_ERR, "malloc: %s", strerror(errno));
        goto oom;
    }
    if ((io.xml_path = calloc(1, 1)) == NULL) {
        (*config->log)(LOG_ERR, "calloc: %s", strerror(errno));
        goto oom;
    }

    int listcount = 0;
    if(config->maxKeys > LIST_BLOCKS_CHUNK)  // http request lists max 1000 blocks at a time
        config->maxKeys = LIST_BLOCKS_CHUNK;
    /* List blocks */
    do {
        const time_t now = time(NULL);

	/* Stop listing object if shutting down */
	if (priv->shutting_down) {
	    r = EAGAIN;
	    goto fail;
	}

        /* Reset XML parser state */
        XML_ParserReset(io.xml, NULL);
        XML_SetUserData(io.xml, &io);
        XML_SetElementHandler(io.xml, http_io_list_elem_start, http_io_list_elem_end);
        XML_SetCharacterDataHandler(io.xml, http_io_list_text);

        /* Format URL */
        snprintf(urlbuf, sizeof(urlbuf), "%s%s?", config->baseURL, config->vhost ? "" : config->bucket);

        /*
         * Add URL parameters (note: must be in "canonical query string" format for proper authentication).
         * Careful to remember about block number bit reversal when recording the marker.
         */
        if (io.list_truncated) {
       
        /*    snprintf(urlbuf + strlen(urlbuf), sizeof(urlbuf) - strlen(urlbuf), "%s=%s%0*jx&",
                     LIST_PARAM_MARKER, config->prefix, CB_BLOCK_NUM_DIGITS,
                     config->name_hash ? (uintmax_t)bit_reverse(io.last_block) : (uintmax_t)io.last_block);
        */
        /* If we use io.last_block, there is a chance that it does not get updated correctly and may end up in infinite loop
         * as io.list_truncated will always be true.
         * config->last_block value is updated in http_io_parse_block() from the xml.
         * Listing of blocks is done based on prefix value, if blocks with the specified prefix are present with same block_size
         * then, those blocks are listed. If blocks are existing without any prefix value, then, if we dont specify prefix flag,
         * then the blocks are listed.
         * marker parameter value should be correct to get list of blocks, else, we may end up in reading wring data.
         */
               snprintf(urlbuf + strlen(urlbuf), sizeof(urlbuf) - strlen(urlbuf), "%s=%s%0*jx&",
                     LIST_PARAM_MARKER, config->prefix, CB_BLOCK_NUM_DIGITS,
                     config->name_hash ? (uintmax_t)bit_reverse(config->last_block) : (uintmax_t)config->last_block);
             
        }
       
        snprintf(urlbuf + strlen(urlbuf), sizeof(urlbuf) - strlen(urlbuf), "%s=%u", LIST_PARAM_MAX_KEYS, config->maxKeys);
        snprintf(urlbuf + strlen(urlbuf), sizeof(urlbuf) - strlen(urlbuf), "&%s=%s", LIST_PARAM_PREFIX, config->prefix);
      
        /* Add Date header */
        http_io_add_date(priv, &io, now);

        /* Add Authorization header */
        if ((r = http_io_add_auth(priv, &io, now, NULL, 0)) != 0)
            goto fail;

        /* Perform operation */
        r = http_io_perform_io(priv, &io, http_io_list_prepper);

        /* Clean up headers */
        curl_slist_free_all(io.headers);
        io.headers = NULL;

        /* Check for error */
        if (r != 0)
            goto fail;

        /* Finalize parse */
        if (XML_Parse(io.xml, NULL, 0, 1) != XML_STATUS_OK) {
            io.xml_error = XML_GetErrorCode(io.xml);
            io.xml_error_line = XML_GetCurrentLineNumber(io.xml);
            io.xml_error_column = XML_GetCurrentColumnNumber(io.xml);
        }

        /* Check for XML error */
        if (io.xml_error != XML_ERROR_NONE) {
            (*config->log)(LOG_ERR, "XML parse error: line %d col %d: %s",
              io.xml_error_line, io.xml_error_column, XML_ErrorString(io.xml_error));
            r = EIO;
            goto fail;
        }
        /* break in case of infinite loop */
        listcount+= config->maxKeys;
        if(listcount >= config->num_blocks)
            break; 
    } while (io.list_truncated);

    /* Done */
    XML_ParserFree(io.xml);
    free(io.xml_path);
    free(io.xml_text);
    return 0;

oom:
    /* Update stats */
    pthread_mutex_lock(&priv->mutex);
    priv->stats.out_of_memory_errors++;
    pthread_mutex_unlock(&priv->mutex);
    r = ENOMEM;

fail:
    /* Clean up after failure */
    if (io.xml != NULL)
        XML_ParserFree(io.xml);
    free(io.xml_path);
    free(io.xml_text);
    return r;
}

/* Parsers defined */
void file_size_parser(char *buf, struct http_io *io)
{
     char delim[] = ": ";
     char* token;
     if (strstr(buf, io->config->http_io_params->file_size_header)){
        for (token = strtok(buf, delim); token; token = strtok(NULL, delim)){
           if (!strstr(token, io->config->http_io_params->file_size_header))
               (void)sscanf(token, "%ju", &io->file_size);
        }  
    }
}

void block_size_parser(char *buf, struct http_io *io)
{
    char delim[] = ": ";
    char* token;
    if (strstr(buf, io->config->http_io_params->block_size_header)){
        for (token = strtok(buf, delim); token; token = strtok(NULL, delim)){
           if (!strstr(token, io->config->http_io_params->block_size_header))
               (void) sscanf(token, "%u", &io->block_size);
        }
    }
}

void name_hash_parser(char *buf, struct http_io *io)
{
    char delim[] = ": ";
    char* token;
    if (strstr(buf, io->config->http_io_params->name_hash_header)){
        for (token = strtok(buf, delim); token; token = strtok(NULL, delim)){
            if (!strstr(token, io->config->http_io_params->name_hash_header)){
                char pbuf[8];
                if (sscanf(token,  "%s", pbuf)) {
                    if (strncmp(pbuf, "yes", sizeof("yes")) == 0)
                        io->name_hash = 1;
                     else
                        io->name_hash = 0;
                }
            }
        }
    }
}

void compression_parser(char *buf, struct http_io *io)
{
    char delim[] = ": ";
    char* token;
    if (strstr(buf, io->config->http_io_params->compression_level_header)){
        for (token = strtok(buf, delim); token; token = strtok(NULL, delim)){
            if (!strstr(token, io->config->http_io_params->compression_level_header)){
               (void) sscanf(token, "%u", &io->compression_level);               
            }
        }
    }
}

void encryption_parser(char *buf, struct http_io *io)
{
    char delim[] = ": ";
    char* token;
    if (strstr(buf, io->config->http_io_params->encrypted_header)){
        for (token = strtok(buf, delim); token; token = strtok(NULL, delim)){
            if (!strstr(token, io->config->http_io_params->encrypted_header)){
                char pbuf[8];
                if (sscanf(token,  "%s", pbuf)) {
                    if (strncmp(pbuf, "yes", sizeof("yes")) == 0)
                        io->is_encrypted = 1;
                     else
                        io->is_encrypted = 0;
                }
            }
        }
    }
}

void encryption_cipher_parser(char *buf, struct http_io *io)
{
    char delim[] = ": ";
    char* token;
    if (strstr(buf, io->config->http_io_params->encryption_cipher_header)){
        for (token = strtok(buf, delim); token; token = strtok(NULL, delim)){
           if (!strstr(token, io->config->http_io_params->encryption_cipher_header)){
               char c[20];
               int i,j=0;
               /* due to some reason http response is having cipher format cipher-name\r\n */
               /* remove CRLF characters */
               for(i=0; i< strlen(token); i++) {
                   if(token[i] != '\n' && token[i] != '\r') {
                       c[j] = token[i];
                       j++;
                   }
               }
               c[j] = '\0';
               io->encryption_cipher = strdup(c);
           } 
        } 
    }
}

void etag_parser(char *buf, struct http_io *io)
{
    char fmtbuf[64];
    if (strncasecmp(buf, ETAG_HEADER ":", sizeof(ETAG_HEADER)) == 0) {
        char md5buf[MD5_DIGEST_LENGTH * 2 + 1];

        snprintf(fmtbuf, sizeof(fmtbuf), " \"%%%uc\"", MD5_DIGEST_LENGTH * 2);
        if (sscanf(buf + sizeof(ETAG_HEADER), fmtbuf, md5buf) == 1)
            http_io_parse_hex(md5buf, io->md5, MD5_DIGEST_LENGTH);
    }
}

void hmac_parser(char *buf, struct http_io *io)
{
    char fmtbuf[64];
    if (strncasecmp(buf, S3B_HMAC_HEADER ":", sizeof(S3B_HMAC_HEADER)) == 0) {
        char hmacbuf[SHA_DIGEST_LENGTH * 2 + 1];

        snprintf(fmtbuf, sizeof(fmtbuf), " \"%%%uc\"", SHA_DIGEST_LENGTH * 2);
        if (sscanf(buf + sizeof(S3B_HMAC_HEADER), fmtbuf, hmacbuf) == 1)
            http_io_parse_hex(hmacbuf, io->hmac, SHA_DIGEST_LENGTH);
    }
}

void encoding_parser(char *buf, struct http_io *io)
{
    if (strncasecmp(buf, CONTENT_ENCODING_HEADER ":", sizeof(CONTENT_ENCODING_HEADER)) == 0) {
        size_t celen;
        char *state;
        char *s;

        *io->content_encoding = '\0';
        for (s = strtok_r(buf + sizeof(CONTENT_ENCODING_HEADER), WHITESPACE ",", &state); s != NULL; s = strtok_r(NULL, WHITESPACE ",", &state)) {
            celen = strlen(io->content_encoding);
            snprintf(io->content_encoding + celen, sizeof(io->content_encoding) - celen, "%s%s", celen > 0 ? "," : "", s);
        }
    }
}

/*
 * Parse a block's item name (including prefix) and set the corresponding bit in the bitmap.
 *
 * The assumption is that there might be various objects in the bucket, e.g. ones created
 * with and without a given prefix, while the operating instance is invoked without the
 * explicit '--prefix' argument. In this case, the correct behavior is to silently ignore
 * the objects whose name does not parse properly.
 * In other cases, however, the somewhat relaxed parsing behavior might lead to errors
 * gone unnoticed, and --listBlocks/--erase not quite working properly.
 */
int
http_io_parse_block(struct http_io_conf *config, const char *name, cb_block_t *block_nump)
{
    const size_t plen = strlen(config->prefix);
    cb_block_t block_num = 0;
    int i;

    /* Check prefix */
    if ( (strlen(config->prefix) > 0) && (strncmp(name, config->prefix, plen) != 0) ) 
        return -1;

    name += plen;

    /* Parse block number */
    for (i = 0; i < CB_BLOCK_NUM_DIGITS; i++) {
        char ch = name[i];

        if (!isxdigit(ch))
            break;
        block_num <<= 4;
        block_num |= ch <= '9' ? ch - '0' : tolower(ch) - 'a' + 10;
    }

    if (config->name_hash)
        block_num = bit_reverse(block_num);

    /* Was parse successful? */
    if (i != CB_BLOCK_NUM_DIGITS || name[i] != '\0' || block_num >= config->num_blocks)
        return -1;

    /* Done */
    config->last_block = block_num;
    *block_nump = block_num;
    return 0;
}
static int
http_io_meta_data(struct cloudbacker_store *cb)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;
    char urlbuf[URL_BUF_SIZE(config)+sizeof(ZERO_FILLED_META_DATA_BLOCK)];
    const time_t now = time(NULL);
    struct http_io io;
    int r = 0;

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = cb_header_parser;
    io.url = urlbuf;
    io.method = HTTP_HEAD;

    /* Construct URL for the first block */
    http_io_get_meta_data_block_url(urlbuf, sizeof(urlbuf), config);

    /* Add Date header */
    http_io_add_date(priv, &io, now);

    /* Add Authorization header */
    if ((r = http_io_add_auth(priv, &io, now, NULL, 0)) != 0)
        goto done;

    /* Perform operation */
    if ((r = http_io_perform_io(priv, &io, http_io_head_prepper)) != 0)
        goto done;
    /* Extract filesystem sizing information */
    if (io.file_size == 0 || io.block_size == 0) {
        r = ENOENT;
        goto done;
    }
    config->http_metadata.file_size = (uintmax_t)io.file_size;
    config->http_metadata.block_size = io.block_size;
    config->http_metadata.name_hash = io.name_hash;
    config->http_metadata.compression_level = io.compression_level;
    config->http_metadata.is_encrypted = io.is_encrypted;
    if(config->http_metadata.is_encrypted)
        config->http_metadata.encryption_cipher = strdup(io.encryption_cipher);

done:
    /*  Clean up */
    curl_slist_free_all(io.headers);
    return r;
}
static int
http_io_set_mounted(struct cloudbacker_store *cb, int *old_valuep, int new_value)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;
    char urlbuf[URL_BUF_SIZE(config) + sizeof(MOUNTED_FLAG)];
    const time_t now = time(NULL);
    struct http_io io;
    int r = 0;

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = cb_header_parser;
    io.url = urlbuf;
    io.method = HTTP_HEAD;

    /* Construct URL for the mounted flag */
    http_io_get_mounted_flag_url(urlbuf, sizeof(urlbuf), config);

    /* Get old value */
    if (old_valuep != NULL) {

        /* Add Date header */
        http_io_add_date(priv, &io, now);

        /* Add Authorization header */
        if ((r = http_io_add_auth(priv, &io, now, NULL, 0)) != 0)
            goto done;

        /* See if object exists */
        switch ((r = http_io_perform_io(priv, &io, http_io_head_prepper))) {
        case ENOENT:
            *old_valuep = 0;
            r = 0;
            break;
        case 0:
            *old_valuep = 1;
            break;
        default:
            goto done;
        }
    }
    /* Set new value */
    if (new_value != -1) {
        char content[_POSIX_HOST_NAME_MAX + DATE_BUF_SIZE + 32];
        u_char md5[MD5_DIGEST_LENGTH];
        char md5buf[MD5_DIGEST_LENGTH * 2 + 1];
        MD5_CTX ctx;

        /* Reset I/O info */
        curl_slist_free_all(io.headers);
        memset(&io, 0, sizeof(io));
        io.url = urlbuf;
        io.method = new_value ? HTTP_PUT : HTTP_DELETE;

        /* Add Date header */
        http_io_add_date(priv, &io, now);

        /* To set the flag PUT some content containing current date */
        if (new_value) {
            struct tm tm;

            /* Create content for the mounted flag object (timestamp) */
            gethostname(content, sizeof(content) - 1);
            content[sizeof(content) - 1] = '\0';
            /* For simplicity, lets use HTTP date format for both s3 and gs, only for this request */
            strftime(content + strlen(content), sizeof(content) - strlen(content), "\n"  HTTP_DATE_BUF_FMT "\n" , gmtime_r(&now, &tm));
            io.src = content;
            io.buf_size = strlen(content);
            MD5_Init(&ctx);
            MD5_Update(&ctx, content, strlen(content));
            MD5_Final(md5, &ctx);

            /* Add Content-Type header */
            io.headers = http_io_add_header(io.headers, "%s: %s", CTYPE_HEADER, MOUNTED_FLAG_CONTENT_TYPE);

            /* Add Content-MD5 header */
            http_io_base64_encode(md5buf, sizeof(md5buf), md5, MD5_DIGEST_LENGTH);
            io.headers = http_io_add_header(io.headers, "%s: %s", MD5_HEADER, md5buf);
        }
        /* Add ACL header (PUT only) */
        if (new_value)
            io.headers = http_io_add_header(io.headers, "%s: %s", priv->config->http_io_params->acl_header,  priv->config->http_io_params->acl_headerval);

        /* Add storage class header (if needed) */
        if (strcasecmp(config->storageClass, SCLASS_S3_REDUCED_REDUNDANCY)==0){
            io.headers = http_io_add_header(io.headers, "%s: %s", priv->config->http_io_params->storage_class_header, 
                                                                  priv->config->http_io_params->storage_class_headerval);
        }

        /* Add Authorization header */
        if ((r = http_io_add_auth(priv, &io, now, io.src, io.buf_size)) != 0)
            goto done;

        /* Perform operation to set or clear mounted flag */
        r = http_io_perform_io(priv, &io, http_io_write_prepper);
    }

done:
    /*  Clean up */
    curl_slist_free_all(io.headers);
    return r;
}


char *
parse_json_field(struct http_io_private *priv, const char *json, const char *field)
{
    struct http_io_conf *const config = priv->config;
    regmatch_t match[2];
    regex_t regex;
    char buf[128];
    char *value;
    size_t vlen;
    int r;

    snprintf(buf, sizeof(buf), "\"%s\"[[:space:]]*:[[:space:]]*\"([^\"]+)\"", field);
    memset(&regex, 0, sizeof(regex));
    if ((r = regcomp(&regex, buf, REG_EXTENDED)) != 0) {
        regerror(r, &regex, buf, sizeof(buf));
        (*config->log)(LOG_INFO, "regex compilation failed: %s", buf);
        errno = EINVAL;
        return NULL;
    }
    if ((r = regexec(&regex, json, sizeof(match) / sizeof(*match), match, 0)) != 0) {
        regerror(r, &regex, buf, sizeof(buf));
        (*config->log)(LOG_INFO, "failed to find JSON field \"%s\" in credentials response: %s", field, buf);
        regfree(&regex);
        errno = EINVAL;
        return NULL;
    }
    regfree(&regex);
    vlen = match[1].rm_eo - match[1].rm_so;
    if ((value = malloc(vlen + 1)) == NULL) {
        r = errno;
        (*config->log)(LOG_INFO, "malloc: %s", strerror(r));
        errno = r;
        return NULL;
    }
    memcpy(value, json + match[1].rm_so, vlen);
    value[vlen] = '\0';
    return value;
}
static int
http_io_read_block(struct cloudbacker_store *const cb, cb_block_t block_num, void *dest,
  u_char *actual_md5, const u_char *expect_md5, int strict)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;
    char urlbuf[URL_BUF_SIZE(config)];
    const time_t now = time(NULL);
    int encrypted = 0;
    struct http_io io;
    u_int did_read;
    char *layer;
    int r;

    /* Sanity check */
    if (config->block_size == 0 || block_num >= config->num_blocks)
        return EINVAL;

    /* Read zero blocks when bitmap indicates empty until non-zero content is written */
    if (priv->non_zero != NULL) {
        const int bits_per_word = sizeof(*priv->non_zero) * 8;
        const int word = block_num / bits_per_word;
        const int bit = 1 << (block_num % bits_per_word);
    
        pthread_mutex_lock(&priv->mutex);
        if ((priv->non_zero[word] & bit) == 0 && priv->non_zero_complete == HTTP_IO_BITMAP_DONE) {
            priv->stats.empty_blocks_read++;
            pthread_mutex_unlock(&priv->mutex);
            memset(dest, 0, config->block_size);
            if (actual_md5 != NULL)
                memset(actual_md5, 0, MD5_DIGEST_LENGTH);
            return 0;
        }
        pthread_mutex_unlock(&priv->mutex);
    }

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = cb_header_parser;
    io.url = urlbuf;
    io.method = HTTP_GET;
    io.block_num = block_num;

    /* Allocate a buffer in case compressed and/or encrypted data is larger */
    io.buf_size = compressBound(config->block_size) + EVP_MAX_IV_LENGTH;
    if ((io.dest = malloc(io.buf_size)) == NULL) {
        (*config->log)(LOG_ERR, "malloc: %s", strerror(errno));
        pthread_mutex_lock(&priv->mutex);
        priv->stats.out_of_memory_errors++;
        pthread_mutex_unlock(&priv->mutex);
        return ENOMEM;
    }

    /* Construct URL for this block */
    http_io_get_block_url(urlbuf, sizeof(urlbuf), config, block_num);

    /* Add Date header */
    http_io_add_date(priv, &io, now);

    /* Add If-Match or If-None-Match header as required */
    if (expect_md5 != NULL && memcmp(expect_md5, zero_md5, MD5_DIGEST_LENGTH) != 0) {
        char md5buf[MD5_DIGEST_LENGTH * 2 + 1];
        const char *header;

        if (strict)
            header = IF_MATCH_HEADER;
        else {
            header = IF_NONE_MATCH_HEADER;
            io.expect_304 = 1;
        }
        http_io_prhex(md5buf, expect_md5, MD5_DIGEST_LENGTH);
        io.headers = http_io_add_header(io.headers, "%s: \"%s\"", header, md5buf);
    }

    /* Add Authorization header */
    if ((r = http_io_add_auth(priv, &io, now, NULL, 0)) != 0)
        goto fail;

    /* Perform operation */
    r = http_io_perform_io(priv, &io, http_io_read_prepper);

    /* Determine how many bytes we read */
    did_read = io.buf_size - io.bufs.rdremain;

    /* Check Content-Encoding and decode if necessary */
    for ( ; r == 0 && *io.content_encoding != '\0'; *layer = '\0') {

        /* Find next encoding layer */
        if ((layer = strrchr(io.content_encoding, ',')) != NULL)
            *layer++ = '\0';
        else
            layer = io.content_encoding;

        /* Sanity check */
        if (io.dest == NULL)
            goto bad_encoding;

        /* Check for encryption (which must have been applied after compression) */
        if (strncasecmp(layer, CONTENT_ENCODING_ENCRYPT "-", sizeof(CONTENT_ENCODING_ENCRYPT)) == 0) {
            const char *const block_cipher = layer + sizeof(CONTENT_ENCODING_ENCRYPT);
            u_char hmac[SHA_DIGEST_LENGTH];
            u_char *buf;

            /* Encryption must be enabled */
            if (config->encryption == NULL) {
                (*config->log)(LOG_ERR, "block %0*jx is encrypted with `%s' but `--encrypt' was not specified",
                  CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num, block_cipher);
                r = EIO;
                break;
            }

            /* Verify encryption type */
            if (strcasecmp(block_cipher, EVP_CIPHER_name(priv->cipher)) != 0) {
                (*config->log)(LOG_ERR, "block %0*jx was encrypted using `%s' but `%s' encryption is configured",
                  CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num, block_cipher, EVP_CIPHER_name(priv->cipher));
                r = EIO;
                break;
            }

            /* Verify block's signature */
            if (memcmp(io.hmac, zero_hmac, sizeof(io.hmac)) == 0) {
                (*config->log)(LOG_ERR, "block %0*jx is encrypted, but no signature was found",
                  CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num);
                r = EIO;
                break;
            }
            http_io_authsig(priv, block_num, io.dest, did_read, hmac);
            if (memcmp(io.hmac, hmac, sizeof(hmac)) != 0) {
                (*config->log)(LOG_ERR, "block %0*jx has an incorrect signature (did you provide the right password?)",
                  CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num);
                r = EIO;
                break;
            }

            /* Allocate buffer for the decrypted data */
            if ((buf = malloc(did_read + EVP_MAX_IV_LENGTH)) == NULL) {
                (*config->log)(LOG_ERR, "malloc: %s", strerror(errno));
                pthread_mutex_lock(&priv->mutex);
                priv->stats.out_of_memory_errors++;
                pthread_mutex_unlock(&priv->mutex);
                r = ENOMEM;
                break;
            }

            /* Decrypt the block */
            did_read = http_io_crypt(priv, block_num, 0, io.dest, did_read, buf);
            memcpy(io.dest, buf, did_read);
            free(buf);

            /* Proceed */
            encrypted = 1;
            continue;
        }

        /* Check for compression */
        if (strcasecmp(layer, CONTENT_ENCODING_DEFLATE) == 0) {
            u_long uclen = config->block_size;

            switch (uncompress(dest, &uclen, io.dest, did_read)) {
            case Z_OK:
                did_read = uclen;
                free(io.dest);
                io.dest = NULL;         /* compression should have been first */
                r = 0;
                break;
            case Z_MEM_ERROR:
                (*config->log)(LOG_ERR, "zlib uncompress: %s", strerror(ENOMEM));
                pthread_mutex_lock(&priv->mutex);
                priv->stats.out_of_memory_errors++;
                pthread_mutex_unlock(&priv->mutex);
                r = ENOMEM;
                break;
            case Z_BUF_ERROR:
                (*config->log)(LOG_ERR, "zlib uncompress: %s", "decompressed block is oversize");
                r = EIO;
                break;
            case Z_DATA_ERROR:
                (*config->log)(LOG_ERR, "zlib uncompress: %s", "data is corrupted or truncated");
                r = EIO;
                break;
            default:
                (*config->log)(LOG_ERR, "unknown zlib compress2() error %d", r);
                r = EIO;
                break;
            }

            /* Proceed */
            continue;
        }

bad_encoding:
        /* It was something we don't recognize */
        (*config->log)(LOG_ERR, "read of block %0*jx returned unexpected encoding \"%s\"",
          CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num, layer);
        r = EIO;
        break;
    }

    /* Check for required encryption */
    if (r == 0 && config->encryption != NULL && !encrypted) {
        (*config->log)(LOG_ERR, "block %0*jx was supposed to be encrypted but wasn't", CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num);
        r = EIO;
    }

    /* Check for wrong length read */
    if (r == 0 && did_read != config->block_size) {
        (*config->log)(LOG_ERR, "read of block %0*jx returned %lu != %lu bytes",
          CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num, (u_long)did_read, (u_long)config->block_size);
        r = EIO;
    }

    /* Copy the data to the desination buffer (if we haven't already) */
    if (r == 0 && io.dest != NULL)
        memcpy(dest, io.dest, config->block_size);

    /* Update stats */
    pthread_mutex_lock(&priv->mutex);
    switch (r) {
        case 0:
            priv->stats.normal_blocks_read++;
            break;
        case ENOENT:
            priv->stats.zero_blocks_read++;
            break;
        default:
            break;
    }
    pthread_mutex_unlock(&priv->mutex);

    /* Check expected MD5 */
    if (expect_md5 != NULL) {
        const int expected_not_found = memcmp(expect_md5, zero_md5, MD5_DIGEST_LENGTH) == 0;

        /* Compare result with expectation */
        switch (r) {
        case 0:
            if (expected_not_found)
                r = strict ? EIO : 0;
            break;
        case ENOENT:
            if (expected_not_found)
                r = strict ? 0 : EEXIST;
            break;
        default:
            break;
        }

        /* Update stats */
        if (!strict) {
            switch (r) {
                case 0:
                    pthread_mutex_lock(&priv->mutex);
                    priv->stats.http_mismatch++;
                    pthread_mutex_unlock(&priv->mutex);
                    break;
                case EEXIST:
                    pthread_mutex_lock(&priv->mutex);
                    priv->stats.http_verified++;
                    pthread_mutex_unlock(&priv->mutex);
                    break;
                default:
                    break;
            }
       }
    }

    /* Treat `404 Not Found' all zeroes */
    if (r == ENOENT) {
        memset(dest, 0, config->block_size);
        r = 0;
    }

    /* Copy actual MD5 */
    if (actual_md5 != NULL)
        memcpy(actual_md5, io.md5, MD5_DIGEST_LENGTH);

fail:
    /*  Clean up */
    if (io.dest != NULL)
        free(io.dest);
    curl_slist_free_all(io.headers);
    return r;
}

/*
 * Write meta data block. This block will have zero data.
 * We are writing only user defined meta data like 
 * filesystem size
 * block size
 * name Hashing for blocks
 * encryption cipher or algorithm
 * compression flag
 */

static int 
http_io_set_meta_data(struct cloudbacker_store *cb, int operation)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;
    char urlbuf[URL_BUF_SIZE(config)+ sizeof(ZERO_FILLED_META_DATA_BLOCK)+strlen(config->prefix)];
    const time_t now = time(NULL);
    struct http_io io;
    int r;
    const int zero_contentLength = 0;

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.url = urlbuf;
    io.method = (operation ? HTTP_PUT : HTTP_DELETE);
    io.buf_size = 0;   /* write zero content block */

    /* Construct URL for this block */
    http_io_get_meta_data_block_url(urlbuf, sizeof(urlbuf), config);
    
    /* Add Date header */
    http_io_add_date(priv, &io, now);
       
    /* Add Content-Type header */
   io.headers = http_io_add_header(io.headers, "%s: %s", CTYPE_HEADER, MOUNTED_FLAG_CONTENT_TYPE);

    /* Add Content-Length header with zero */
    io.headers = http_io_add_header(io.headers, "%s: %d", CONTENT_LENGTH, zero_contentLength);

    /* Add ACL header (PUT only) */
    io.headers = http_io_add_header(io.headers, "%s: %s", priv->config->http_io_params->acl_header,priv->config->http_io_params->acl_headerval);

    /* Add meta-data headers  */
    io.headers = http_io_add_header(io.headers, "%s: %u", priv->config->http_io_params->block_size_header,
                                                          config->http_metadata.block_size);

    io.headers = http_io_add_header(io.headers, "%s: %ju", priv->config->http_io_params->file_size_header , 
                                                          (uintmax_t)(config->http_metadata.file_size));

    io.headers = http_io_add_header(io.headers, "%s: %s", priv->config->http_io_params->name_hash_header, config->http_metadata.name_hash ? "yes" : "no");


    io.headers = http_io_add_header(io.headers, "%s: %s", priv->config->http_io_params->encrypted_header, config->http_metadata.is_encrypted ? "yes" : "no");

    if(config->http_metadata.encryption_cipher != NULL)
        io.headers = http_io_add_header(io.headers, "%s: %s", priv->config->http_io_params->encryption_cipher_header, 
                                                              config->http_metadata.encryption_cipher);
    io.headers = http_io_add_header(io.headers, "%s: %d", priv->config->http_io_params->compression_level_header, config->http_metadata.compression_level);
    
    /* Add storage class header (if needed) */
    if (strcasecmp(config->storageClass, SCLASS_S3_REDUCED_REDUNDANCY)==0){
        io.headers = http_io_add_header(io.headers, "%s: %s", priv->config->http_io_params->storage_class_header, 
                                                              priv->config->http_io_params->storage_class_headerval);
    }

    /* Add Authorization header */
    if ((r = http_io_add_auth(priv, &io, now, io.src, io.buf_size)) != 0)
        goto fail;

    /* Perform operation */
    r = http_io_perform_io(priv, &io, http_io_write_prepper);
    if(r == 0) {
        /*  Clean up */
        curl_slist_free_all(io.headers);
        return r;
    }
    goto fail;

  
fail:
    /*  Clean up */
    curl_slist_free_all(io.headers);
    return r;
}

/*
 * Write block if src != NULL, otherwise delete block.
 */
static int
http_io_write_block(struct cloudbacker_store *const cb, cb_block_t block_num, const void *src, u_char *caller_md5,
  check_cancel_t *check_cancel, void *check_cancel_arg)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;
    char urlbuf[URL_BUF_SIZE(config)];
    char md5buf[(MD5_DIGEST_LENGTH * 4) / 3 + 4];
    char hmacbuf[SHA_DIGEST_LENGTH * 2 + 1];
    u_char hmac[SHA_DIGEST_LENGTH];
    u_char md5[MD5_DIGEST_LENGTH];
    const time_t now = time(NULL);
    void *encoded_buf = NULL;
    struct http_io io;
    int compressed = 0;
    int encrypted = 0;
    int r;

    /* Sanity check */
    if (config->block_size == 0 || block_num >= config->num_blocks)
        return EINVAL;

    /* Detect zero blocks (if not done already by upper layer) */
    if (src != NULL) {
        if (http_io_is_zero_block(src, config->block_size))
            src = NULL;
    }

    /* Don't write zero blocks when bitmap indicates empty until non-zero content is written */
    if (priv->non_zero != NULL) {
        const int bits_per_word = sizeof(*priv->non_zero) * 8;
        const int word = block_num / bits_per_word;
        const int bit = 1 << (block_num % bits_per_word);

        pthread_mutex_lock(&priv->mutex);
        if (src == NULL) {
            if ((priv->non_zero[word] & bit) == 0 && priv->non_zero_complete == HTTP_IO_BITMAP_DONE) {
                priv->stats.empty_blocks_written++;
                pthread_mutex_unlock(&priv->mutex);
                return 0;
            }
        } else
            priv->non_zero[word] |= bit;
        pthread_mutex_unlock(&priv->mutex);
    }

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.url = urlbuf;
    io.method = src != NULL ? HTTP_PUT : HTTP_DELETE;
    io.src = src;
    io.buf_size = config->block_size;
    io.block_num = block_num;
    io.check_cancel = check_cancel;
    io.check_cancel_arg = check_cancel_arg;

    /* Compress block if desired */
    if (src != NULL && config->compress != Z_NO_COMPRESSION) {
        u_long compress_len;

        /* Allocate buffer */
        compress_len = compressBound(io.buf_size);
        if ((encoded_buf = malloc(compress_len)) == NULL) {
            (*config->log)(LOG_ERR, "malloc: %s", strerror(errno));
            pthread_mutex_lock(&priv->mutex);
            priv->stats.out_of_memory_errors++;
            pthread_mutex_unlock(&priv->mutex);
            r = ENOMEM;
            goto fail;
        }

        /* Compress data */
        r = compress2(encoded_buf, &compress_len, io.src, io.buf_size, config->compress);
        switch (r) {
            case Z_OK:
                break;
            case Z_MEM_ERROR:
                (*config->log)(LOG_ERR, "zlib compress: %s", strerror(ENOMEM));
                pthread_mutex_lock(&priv->mutex);
                priv->stats.out_of_memory_errors++;
                pthread_mutex_unlock(&priv->mutex);
                r = ENOMEM;
                goto fail;
            default:
                (*config->log)(LOG_ERR, "unknown zlib compress2() error %d", r);
                r = EIO;
                goto fail;
        }

        /* Update POST data */
        io.src = encoded_buf;
        io.buf_size = compress_len;
        compressed = 1;
    }

    /* Encrypt data if desired */
    if (src != NULL && config->encryption != NULL) {
        void *encrypt_buf;
        u_int encrypt_len;

        /* Allocate buffer */
        if ((encrypt_buf = malloc(io.buf_size + EVP_MAX_IV_LENGTH)) == NULL) {
            (*config->log)(LOG_ERR, "malloc: %s", strerror(errno));
            pthread_mutex_lock(&priv->mutex);
            priv->stats.out_of_memory_errors++;
            pthread_mutex_unlock(&priv->mutex);
            r = ENOMEM;
            goto fail;
        }

        /* Encrypt the block */
        encrypt_len = http_io_crypt(priv, block_num, 1, io.src, io.buf_size, encrypt_buf);

        /* Compute block signature */
        http_io_authsig(priv, block_num, encrypt_buf, encrypt_len, hmac);
        http_io_prhex(hmacbuf, hmac, SHA_DIGEST_LENGTH);

        /* Update POST data */
        io.src = encrypt_buf;
        io.buf_size = encrypt_len;
        free(encoded_buf);              /* OK if NULL */
        encoded_buf = encrypt_buf;
        encrypted = 1;
    }
    /* Set Content-Encoding HTTP header */
    if (compressed || encrypted) {
        char ebuf[128];

        snprintf(ebuf, sizeof(ebuf), "%s: ", CONTENT_ENCODING_HEADER);
        if (compressed)
            snprintf(ebuf + strlen(ebuf), sizeof(ebuf) - strlen(ebuf), "%s", CONTENT_ENCODING_DEFLATE);
        if (encrypted) {
            snprintf(ebuf + strlen(ebuf), sizeof(ebuf) - strlen(ebuf), "%s%s-%s",
              compressed ? ", " : "", CONTENT_ENCODING_ENCRYPT, config->encryption);
        }
        io.headers = http_io_add_header(io.headers, "%s", ebuf);
    }

    /* Compute MD5 checksum */
    if (src != NULL)
        MD5(io.src, io.buf_size, md5);
    else
        memset(md5, 0, MD5_DIGEST_LENGTH);

    /* Report MD5 back to caller */
    if (caller_md5 != NULL)
        memcpy(caller_md5, md5, MD5_DIGEST_LENGTH);

    /* Construct URL for this block */
    http_io_get_block_url(urlbuf, sizeof(urlbuf), config, block_num);

    /* Add Date header */
    http_io_add_date(priv, &io, now);

    /* Add PUT-only headers */
    if (src != NULL) {

        /* Add Content-Type header */
        io.headers = http_io_add_header(io.headers, "%s: %s", CTYPE_HEADER, CONTENT_TYPE);

        /* Add Content-MD5 header */
        http_io_base64_encode(md5buf, sizeof(md5buf), md5, MD5_DIGEST_LENGTH);
        io.headers = http_io_add_header(io.headers, "%s: %s", MD5_HEADER, md5buf);
    }

    /* Add ACL header (PUT only) */
    if (src != NULL)
        io.headers = http_io_add_header(io.headers, "%s: %s", priv->config->http_io_params->acl_header,priv->config->http_io_params->acl_headerval);

    /* Add signature header (if encrypting) */
    if (src != NULL && config->encryption != NULL)
        io.headers = http_io_add_header(io.headers, "%s: \"%s\"", priv->config->http_io_params->HMAC_Header, hmacbuf);

    /* Add storage class header (if needed) */
    if (strcasecmp(config->storageClass, SCLASS_S3_REDUCED_REDUNDANCY)==0){
         io.headers = http_io_add_header(io.headers, "%s: %s", priv->config->http_io_params->storage_class_header, priv->config->http_io_params->storage_class_headerval);
    }

    /* Add Authorization header */
    if ((r = http_io_add_auth(priv, &io, now, io.src, io.buf_size)) != 0)
        goto fail;

    /* Perform operation */
    r = http_io_perform_io(priv, &io, http_io_write_prepper);

    /* Update stats */
    if (r == 0) {
        pthread_mutex_lock(&priv->mutex);
        if (src == NULL)
            priv->stats.zero_blocks_written++;
        else
            priv->stats.normal_blocks_written++;
        pthread_mutex_unlock(&priv->mutex);
    }

fail:
    /*  Clean up */
    curl_slist_free_all(io.headers);
    if (encoded_buf != NULL)
        free(encoded_buf);
    return r;
}

static int
http_io_read_block_part(struct cloudbacker_store *cb, cb_block_t block_num, u_int off, u_int len, void *dest)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;

    return block_part_read_block_part(cb, block_num, config->block_size, off, len, dest);
}

static int
http_io_write_block_part(struct cloudbacker_store *cb, cb_block_t block_num, u_int off, u_int len, const void *src)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;

    return block_part_write_block_part(cb, block_num, config->block_size, off, len, src);
}


/*
 * Compute authorization hash using secret access key and add Authorization and SHA256 hash headers.
 *
 * Note: headers must be unique and not wrapped.
 */
int
http_io_add_auth(struct http_io_private *priv, struct http_io *const io, time_t now, const void *payload, size_t plen)
{
    const struct http_io_conf *const config = priv->config;
    
    return (*config->authenticate)(priv, io, now, payload, plen);
}

/*
 * Create URL for a meta data block, and return pointer to the URL's URI path.
 */
void
http_io_get_meta_data_block_url(char *buf, size_t bufsiz, struct http_io_conf *config)
{
    int len;

    if (config->vhost)
        len = snprintf(buf, bufsiz, "%s%s%s", config->baseURL, config->prefix, ZERO_FILLED_META_DATA_BLOCK);
    else {
        len = snprintf(buf, bufsiz, "%s%s/%s%s", config->baseURL,
                       config->bucket, config->prefix, ZERO_FILLED_META_DATA_BLOCK);
    }
    (void)len;                  /* avoid compiler warning when NDEBUG defined */
    assert(len < bufsiz);
}

/*
 * Create URL for a block, and return pointer to the URL's URI path.
 */
void
http_io_get_block_url(char *buf, size_t bufsiz, struct http_io_conf *config, cb_block_t block_num)
{
    int len;

    if (config->vhost)
        len = snprintf(buf, bufsiz, "%s%s%0*jx", config->baseURL, config->prefix, CB_BLOCK_NUM_DIGITS,
                       config->name_hash ? (uintmax_t)bit_reverse(block_num) : (uintmax_t)block_num);
    else {
        len = snprintf(buf, bufsiz, "%s%s/%s%0*jx", config->baseURL,
                       config->bucket, config->prefix, CB_BLOCK_NUM_DIGITS,
                       config->name_hash ? (uintmax_t)bit_reverse(block_num) : (uintmax_t)block_num);
    }
    (void)len;                  /* avoid compiler warning when NDEBUG defined */
    assert(len < bufsiz);
}

/*
 * Create URL for a bucket, and return pointer to the URL's URI path.
 */

void
http_io_get_bucket_url(char *buf, size_t bufsiz, struct http_io_conf *config)
{
    int len;

    if (config->vhost)
        len = snprintf(buf, bufsiz, "%s%s", config->baseURL, config->bucket);
    else
        len = snprintf(buf, bufsiz, "%s%s/", config->baseURL, config->bucket);
    (void)len;                  /* avoid compiler warning when NDEBUG defined */
    assert(len < bufsiz);

}

/*
 * Create URL for the mounted flag, and return pointer to the URL's path not including any "/bucket" prefix.
 */
void
http_io_get_mounted_flag_url(char *buf, size_t bufsiz, struct http_io_conf *config)
{
    int len;

    if (config->vhost)
        len = snprintf(buf, bufsiz, "%s%s%s", config->baseURL, config->prefix, MOUNTED_FLAG);
    else
        len = snprintf(buf, bufsiz, "%s%s/%s%s", config->baseURL, config->bucket, config->prefix, MOUNTED_FLAG);
    (void)len;                  /* avoid compiler warning when NDEBUG defined */
    assert(len < bufsiz);
}


static void
http_io_openssl_locker(int mode, int i, const char *file, int line)
{
    if ((mode & CRYPTO_LOCK) != 0)
        pthread_mutex_lock(&openssl_locks[i]);
    else
        pthread_mutex_unlock(&openssl_locks[i]);
}
static u_long
http_io_openssl_ider(void)
{
    return (u_long)pthread_self();
}

void
http_io_base64_encode(char *buf, size_t bufsiz, const void *data, size_t len)
{
    BUF_MEM *bptr;
    BIO* bmem;
    BIO* b64;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data, len);
    (void)BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    snprintf(buf, bufsiz, "%.*s", (int)bptr->length - 1, (char *)bptr->data);
    BIO_free_all(b64);
}

int
http_io_is_zero_block(const void *data, u_int block_size)
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

/*
 * Encrypt or decrypt one block
 */
u_int
http_io_crypt(struct http_io_private *priv, cb_block_t block_num, int enc, const u_char *src, u_int len, u_char *dest)
{
    u_char ivec[EVP_MAX_IV_LENGTH];
    EVP_CIPHER_CTX ctx;
    u_int total_len;
    char blockbuf[EVP_MAX_IV_LENGTH];
    int clen;
    int r;

#ifdef NDEBUG
    /* Avoid unused variable warning */
    (void)r;
#endif

    /* Sanity check */
    assert(EVP_MAX_IV_LENGTH >= MD5_DIGEST_LENGTH);

    /* Initialize cipher context */
    EVP_CIPHER_CTX_init(&ctx);

    /* Generate initialization vector by encrypting the block number using previously generated IV */
    memset(blockbuf, 0, sizeof(blockbuf));
    snprintf(blockbuf, sizeof(blockbuf), "%0*jx", CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num);

    /* Initialize cipher for IV generation */
    r = EVP_EncryptInit_ex(&ctx, priv->cipher, NULL, priv->ivkey, priv->ivkey);
    assert(r == 1);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    /* Encrypt block number to get IV for bulk encryption */
    r = EVP_EncryptUpdate(&ctx, ivec, &clen, (const u_char *)blockbuf, EVP_CIPHER_CTX_block_size(&ctx));
    assert(r == 1 && clen == EVP_CIPHER_CTX_block_size(&ctx));
    r = EVP_EncryptFinal_ex(&ctx, NULL, &clen);
    assert(r == 1 && clen == 0);

    /* Re-initialize cipher for bulk data encryption */
    assert(EVP_CIPHER_CTX_block_size(&ctx) == EVP_CIPHER_CTX_iv_length(&ctx));
    r = EVP_CipherInit_ex(&ctx, priv->cipher, NULL, priv->key, ivec, enc);
    assert(r == 1);
    EVP_CIPHER_CTX_set_padding(&ctx, 1);
    /* Encrypt/decrypt */
    r = EVP_CipherUpdate(&ctx, dest, &clen, src, (int)len);
    assert(r == 1 && clen >= 0);
    total_len = (u_int)clen;
    r = EVP_CipherFinal_ex(&ctx, dest + total_len, &clen);
    assert(r == 1 && clen >= 0);
    total_len += (u_int)clen;

    /* Encryption debug */
#if DEBUG_ENCRYPTION
{
    struct http_io_conf *const config = priv->config;
    char ivecbuf[sizeof(ivec) * 2 + 1];
    http_io_prhex(ivecbuf, ivec, sizeof(ivec));
    (*config->log)(LOG_DEBUG, "%sCRYPT: block=%s ivec=0x%s len: %d -> %d", (enc ? "EN" : "DE"), blockbuf, ivecbuf, len, total_len);
}
#endif

    /* Done */
    EVP_CIPHER_CTX_cleanup(&ctx);
    return total_len;
}

void
http_io_authsig(struct http_io_private *priv, cb_block_t block_num, const u_char *src, u_int len, u_char *hmac)
{
    const char *const ciphername = EVP_CIPHER_name(priv->cipher);
    char blockbuf[64];
    u_int hmac_len;
    HMAC_CTX ctx;

    /* Sign the block number, the name of the encryption algorithm, and the block data */
    snprintf(blockbuf, sizeof(blockbuf), "%0*jx", CB_BLOCK_NUM_DIGITS, (uintmax_t)block_num);
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, (const u_char *)priv->key, priv->keylen, EVP_sha1(), NULL);
    HMAC_Update(&ctx, (const u_char *)blockbuf, strlen(blockbuf));
    HMAC_Update(&ctx, (const u_char *)ciphername, strlen(ciphername));
    HMAC_Update(&ctx, (const u_char *)src, len);
    HMAC_Final(&ctx, (u_char *)hmac, &hmac_len);
    assert(hmac_len == SHA_DIGEST_LENGTH);
    HMAC_CTX_cleanup(&ctx);
}

void
update_hmac_from_header(HMAC_CTX *const ctx, struct http_io *const io,
  const char *name, int value_only, char *sigbuf, size_t sigbuflen)
{
    const struct curl_slist *header;
    const char *colon;
    const char *value;
    size_t name_len;

    /* Find and add header */
    name_len = (colon = strchr(name, ':')) != NULL ? colon - name : strlen(name);
    for (header = io->headers; header != NULL; header = header->next) {
        if (strncasecmp(header->data, name, name_len) == 0 && header->data[name_len] == ':') {
            if (!value_only) {
                HMAC_Update(ctx, (const u_char *)header->data, name_len + 1);
#if DEBUG_AUTHENTICATION
                snprintf(sigbuf + strlen(sigbuf), sigbuflen - strlen(sigbuf), "%.*s", name_len + 1, header->data);
#endif
            }
            for (value = header->data + name_len + 1; isspace(*value); value++)
                ;
            HMAC_Update(ctx, (const u_char *)value, strlen(value));
#if DEBUG_AUTHENTICATION
            snprintf(sigbuf + strlen(sigbuf), sigbuflen - strlen(sigbuf), "%s", value);
#endif
            break;
        }
    }

    /* Add newline whether or not header was found */
    HMAC_Update(ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sigbuflen - strlen(sigbuf), "\n");
#endif
}

/*
 * Parse exactly "nbytes" contiguous 2-digit hex bytes.
 * On failure, zero out the buffer and return -1.
 */
int
http_io_parse_hex(const char *str, u_char *buf, u_int nbytes)
{
    int i;

    /* Parse hex string */
    for (i = 0; i < nbytes; i++) {
        int byte;
        int j;

        for (byte = j = 0; j < 2; j++) {
            const char ch = str[2 * i + j];

            if (!isxdigit(ch)) {
                memset(buf, 0, nbytes);
                return -1;
            }
            byte <<= 4;
            byte |= ch <= '9' ? ch - '0' : tolower(ch) - 'a' + 10;
        }
        buf[i] = byte;
    }

    /* Done */
    return 0;
}

void
http_io_prhex(char *buf, const u_char *data, size_t len)
{
    static const char *hexdig = "0123456789abcdef";
    int i;

    for (i = 0; i < len; i++) {
        buf[i * 2 + 0] = hexdig[data[i] >> 4];
        buf[i * 2 + 1] = hexdig[data[i] & 0x0f];
    }
    buf[i * 2] = '\0';
}
int
http_io_strcasecmp_ptr(const void *const ptr1, const void *const ptr2)
{
    const char *const str1 = *(const char *const *)ptr1;
    const char *const str2 = *(const char *const *)ptr2;

    return strcasecmp(str1, str2);
}

/*
 * Perform HTTP operation.
 */
int
http_io_perform_io(struct http_io_private *priv, struct http_io *io, http_io_curl_prepper_t *prepper)
{
    struct http_io_conf *const config = priv->config;
    struct timespec delay;    
    CURLcode curl_code;
    u_int retry_pause = 0;
    u_int total_pause;
    long http_code;
    double clen;
    int attempt;
    CURL *curl;

    /* parser functions require valid io->config */
    io->config = config;
    /* Debug */
    if (config->debug)
        (*config->log)(LOG_DEBUG, "%s %s", io->method, io->url);

    /* Make attempts */
    for (attempt = 0, total_pause = 0; 1; attempt++, total_pause += retry_pause) {

        /* Acquire and initialize CURL instance */
        if ((curl = http_io_acquire_curl(priv, io)) == NULL)
            return EIO;
        (*prepper)(curl, io);

        /* Perform HTTP operation and check result */
        if (attempt > 0)
            (*config->log)(LOG_INFO, "retrying query (attempt #%d): %s %s", attempt + 1, io->method, io->url);
        curl_code = curl_easy_perform(curl);

        /* Find out what the HTTP result code was (if any) */
        switch (curl_code) {
        case CURLE_HTTP_RETURNED_ERROR:
        case 0:
            if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code) != 0)
                http_code = 999;                                /* this should never happen */
            break;
        default:
            http_code = -1;
            break;
        }

        /* Work around the fact that libcurl converts a 304 HTTP code as success */
        if (curl_code == 0 && http_code == HTTP_NOT_MODIFIED)
            curl_code = CURLE_HTTP_RETURNED_ERROR;

        /* In the case of a DELETE, treat an HTTP_NOT_FOUND error as successful */
        if (curl_code == CURLE_HTTP_RETURNED_ERROR
          && http_code == HTTP_NOT_FOUND
          && strcmp(io->method, HTTP_DELETE) == 0)
            curl_code = 0;

        /* Handle success */
        if (curl_code == 0) {
            double curl_time;
            int r = 0;

            /* Extra debug logging */
            if (config->debug)
                (*config->log)(LOG_DEBUG, "success: %s %s", io->method, io->url);

            /* Extract timing info */
            if ((curl_code = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &curl_time)) != CURLE_OK) {
                (*config->log)(LOG_ERR, "can't get cURL timing: %s", curl_easy_strerror(curl_code));
                curl_time = 0.0;
            }

            /* Extract content-length (if required) */
            if (io->content_lengthp != NULL) {
                if ((curl_code = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &clen)) == CURLE_OK)
                    *io->content_lengthp = (u_int)clen;
                else {
                    (*config->log)(LOG_ERR, "can't get content-length: %s", curl_easy_strerror(curl_code));
                    r = ENXIO;
                }
            }

            /* Update stats */
            pthread_mutex_lock(&priv->mutex);
            if (strcmp(io->method, HTTP_GET) == 0) {
                priv->stats.http_gets.count++;
                priv->stats.http_gets.time += curl_time;
            } else if (strcmp(io->method, HTTP_PUT) == 0) {
                priv->stats.http_puts.count++;
                priv->stats.http_puts.time += curl_time;
            } else if (strcmp(io->method, HTTP_DELETE) == 0) {
                priv->stats.http_deletes.count++;
                priv->stats.http_deletes.time += curl_time;
            } else if (strcmp(io->method, HTTP_HEAD) == 0) {
                priv->stats.http_heads.count++;
                priv->stats.http_heads.time += curl_time;
            }
            pthread_mutex_unlock(&priv->mutex);

            /* Done */
            http_io_release_curl(priv, &curl, r == 0);
            return r;
        }

        /* Free the curl handle (and ensure we don't try to re-use it) */
        http_io_release_curl(priv, &curl, 0);

        /* Handle errors */
        switch (curl_code) {
        case CURLE_ABORTED_BY_CALLBACK:
            if (config->debug)
                (*config->log)(LOG_DEBUG, "write aborted: %s %s", io->method, io->url);
            pthread_mutex_lock(&priv->mutex);
            priv->stats.http_canceled_writes++;
            pthread_mutex_unlock(&priv->mutex);
            return ECONNABORTED;
        case CURLE_OPERATION_TIMEDOUT:
            (*config->log)(LOG_NOTICE, "operation timeout: %s %s", io->method, io->url);
            pthread_mutex_lock(&priv->mutex);
            priv->stats.curl_timeouts++;
            pthread_mutex_unlock(&priv->mutex);
            break;
        case CURLE_HTTP_RETURNED_ERROR:                 /* special handling for some specific HTTP codes */
            switch (http_code) {
            case HTTP_NOT_FOUND:
                if (config->debug)
                    (*config->log)(LOG_DEBUG, "rec'd %ld response: %s %s", http_code, io->method, io->url);
                return ENOENT;
            case HTTP_UNAUTHORIZED:
                (*config->log)(LOG_ERR, "rec'd %ld response: %s %s", http_code, io->method, io->url);
                pthread_mutex_lock(&priv->mutex);
                priv->stats.http_unauthorized++;
                pthread_mutex_unlock(&priv->mutex);
                return EACCES;
            case HTTP_FORBIDDEN:
                (*config->log)(LOG_ERR, "rec'd %ld response: %s %s", http_code, io->method, io->url);
                pthread_mutex_lock(&priv->mutex);
                priv->stats.http_forbidden++;
                pthread_mutex_unlock(&priv->mutex);
                return EPERM;
            case HTTP_PRECONDITION_FAILED:
                (*config->log)(LOG_INFO, "rec'd stale content: %s %s", io->method, io->url);
                pthread_mutex_lock(&priv->mutex);
                priv->stats.http_stale++;
                pthread_mutex_unlock(&priv->mutex);
                break;
            case HTTP_NOT_MODIFIED:
                if (io->expect_304) {
                    if (config->debug)
                        (*config->log)(LOG_DEBUG, "rec'd %ld response: %s %s", http_code, io->method, io->url);
                    return EEXIST;
                }
                /* FALLTHROUGH */
            default:
                (*config->log)(LOG_ERR, "rec'd %ld response: %s %s", http_code, io->method, io->url);
                pthread_mutex_lock(&priv->mutex);
                switch (http_code / 100) {
                case 4:
                    priv->stats.http_4xx_error++;
                    break;
                case 5:
                    priv->stats.http_5xx_error++;
                    break;
                default:
                    priv->stats.http_other_error++;
                    break;
                }
                pthread_mutex_unlock(&priv->mutex);
                break;
            }
            break;
        default:
            (*config->log)(LOG_ERR, "operation failed: %s (%s)", curl_easy_strerror(curl_code),
              total_pause >= config->max_retry_pause ? "final attempt" : "will retry");
            pthread_mutex_lock(&priv->mutex);
            switch (curl_code) {
            case CURLE_OUT_OF_MEMORY:
                priv->stats.curl_out_of_memory++;
                break;
            case CURLE_COULDNT_CONNECT:
                priv->stats.curl_connect_failed++;
                break;
            case CURLE_COULDNT_RESOLVE_HOST:
                priv->stats.curl_host_unknown++;
                break;
            default:
                priv->stats.curl_other_error++;
                break;
            }
            pthread_mutex_unlock(&priv->mutex);
            break;
        }

        /* Retry with exponential backoff up to max total pause limit */
        if (total_pause >= config->max_retry_pause)
            break;
        retry_pause = retry_pause > 0 ? retry_pause * 2 : config->initial_retry_pause;
        if (total_pause + retry_pause > config->max_retry_pause)
            retry_pause = config->max_retry_pause - total_pause;
        delay.tv_sec = retry_pause / 1000;
        delay.tv_nsec = (retry_pause % 1000) * 1000000;
        nanosleep(&delay, NULL);            // TODO: check for EINTR

        /* Update retry stats */
        pthread_mutex_lock(&priv->mutex);
        priv->stats.num_retries++;
        priv->stats.retry_delay += retry_pause;
        pthread_mutex_unlock(&priv->mutex);
    }

    /* Give up */
    (*config->log)(LOG_ERR, "giving up on: %s %s", io->method, io->url);
    return EIO;
}


/* 
 * CURL callbacks
 */

void
http_io_list_elem_start(void *arg, const XML_Char *name, const XML_Char **atts)
{
    struct http_io *const io = (struct http_io *)arg;
    const size_t plen = strlen(io->xml_path);
    char *newbuf;

    /* Update current path */
    if ((newbuf = realloc(io->xml_path, plen + 1 + strlen(name) + 1)) == NULL) {
        (*io->config->log)(LOG_DEBUG, "realloc: %s", strerror(errno));
        io->xml_error = XML_ERROR_NO_MEMORY;
        return;
    }
    io->xml_path = newbuf;
    io->xml_path[plen] = '/';
    strcpy(io->xml_path + plen + 1, name);

    /* Reset buffer */
    io->xml_text_len = 0;
    io->xml_text[0] = '\0';
}

void
http_io_list_elem_end(void *arg, const XML_Char *name)
{
    struct http_io *const io = (struct http_io *)arg;
    cb_block_t block_num;

    /* Handle <Truncated> tag */
    if (strcmp(io->xml_path, "/" LIST_ELEM_LIST_BUCKET_RESLT "/" LIST_ELEM_IS_TRUNCATED) == 0)
        io->list_truncated = strcmp(io->xml_text, LIST_TRUE) == 0;

    /* Handle <Key> tag */
    else if (strcmp(io->xml_path, "/" LIST_ELEM_LIST_BUCKET_RESLT "/" LIST_ELEM_CONTENTS "/" LIST_ELEM_KEY) == 0) {
        if (http_io_parse_block(io->config, io->xml_text, &block_num) == 0) {
            (*io->callback_func)(io->callback_arg, block_num);
            io->last_block = block_num;
        }
    }

    /* Update current XML path */
    assert(strrchr(io->xml_path, '/') != NULL);
    *strrchr(io->xml_path, '/') = '\0';

    /* Reset buffer */
    io->xml_text_len = 0;
    io->xml_text[0] = '\0';
}

void
http_io_list_text(void *arg, const XML_Char *s, int len)
{
    struct http_io *const io = (struct http_io *)arg;
    int avail;

    /* Append text to buffer */
    avail = io->xml_text_max - io->xml_text_len;
    if (len > avail)
        len = avail;
    memcpy(io->xml_text + io->xml_text_len, s, len);
    io->xml_text_len += len;
    io->xml_text[io->xml_text_len] = '\0';
}

size_t
http_io_curl_header(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct http_io *const io = (struct http_io *)stream;
    const size_t total = size * nmemb;
    char buf[1024];
    int i;

    /* Null-terminate header */
    if (total > sizeof(buf) - 1)
        return total;
    memcpy(buf, ptr, total);
    buf[total] = '\0';

    /* run the list of parsers as described in the io structure */
    for (i = 0; NULL != io->header_parser[i]; i++) {
        (*io->header_parser[i])(buf, io);
    }

    /* Done */
    return total;
}

size_t
http_io_curl_reader(const void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct http_io *const io = (struct http_io *)stream;
    struct http_io_bufs *const bufs = &io->bufs;
    size_t total = size * nmemb;

    if (total > bufs->rdremain)     /* should never happen */
        total = bufs->rdremain;
    memcpy(bufs->rddata, ptr, total);
    bufs->rddata += total;
    bufs->rdremain -= total;
    return total;
}

size_t
http_io_curl_writer(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct http_io *const io = (struct http_io *)stream;
    struct http_io_bufs *const bufs = &io->bufs;
    size_t total = size * nmemb;

    /* Check for canceled write */
    if (io->check_cancel != NULL && (*io->check_cancel)(io->check_cancel_arg, io->block_num) != 0)
        return CURL_READFUNC_ABORT;

    /* Copy out data */
    if (total > bufs->wrremain)     /* should never happen */
        total = bufs->wrremain;
    memcpy(ptr, bufs->wrdata, total);
    bufs->wrdata += total;
    bufs->wrremain -= total;
    return total;
}

struct curl_slist *
http_io_add_header(struct curl_slist *headers, const char *fmt, ...)
{
    char buf[1024];
    va_list args;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    headers = curl_slist_append(headers, buf);
    va_end(args);
    return headers;
}

CURL *
http_io_acquire_curl(struct http_io_private *priv, struct http_io *io)
{
    struct http_io_conf *const config = priv->config;
    struct curl_holder *holder;
    CURL *curl;

    pthread_mutex_lock(&priv->mutex);
    if ((holder = LIST_FIRST(&priv->curls)) != NULL) {
        curl = holder->curl;
        LIST_REMOVE(holder, link);
        priv->stats.curl_handles_reused++;
        pthread_mutex_unlock(&priv->mutex);
        free(holder);
        curl_easy_reset(curl);
    } else {
        priv->stats.curl_handles_created++;             // optimistic
        pthread_mutex_unlock(&priv->mutex);
        if ((curl = curl_easy_init()) == NULL) {
            pthread_mutex_lock(&priv->mutex);
            priv->stats.curl_handles_created--;         // undo optimistic
            priv->stats.curl_other_error++;
            pthread_mutex_unlock(&priv->mutex);
            (*config->log)(LOG_ERR, "curl_easy_init() failed");
            return NULL;
        }
    }
    curl_easy_setopt(curl, CURLOPT_URL, io->url);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, (long)1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)config->timeout);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, config->user_agent);
    if (config->max_speed[HTTP_UPLOAD] != 0)
        curl_easy_setopt(curl, CURLOPT_MAX_SEND_SPEED_LARGE, (curl_off_t)(config->max_speed[HTTP_UPLOAD] / 8));
    if (config->max_speed[HTTP_DOWNLOAD] != 0)
        curl_easy_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, (curl_off_t)(config->max_speed[HTTP_DOWNLOAD] / 8));
    if (strncmp(io->url, "https", 5) == 0) {
        if (config->insecure)
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (long)0);
        if (config->cacert != NULL)
            curl_easy_setopt(curl, CURLOPT_CAINFO, config->cacert);
    }
    if (config->debug_http)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    return curl;
}

void
http_io_release_curl(struct http_io_private *priv, CURL **curlp, int may_cache)
{
    struct curl_holder *holder;
    CURL *const curl = *curlp;

    *curlp = NULL;
    assert(curl != NULL);
    if (!may_cache) {
        curl_easy_cleanup(curl);
        return;
    }
    if ((holder = calloc(1, sizeof(*holder))) == NULL) {
        curl_easy_cleanup(curl);
        pthread_mutex_lock(&priv->mutex);
        priv->stats.out_of_memory_errors++;
        pthread_mutex_unlock(&priv->mutex);
        return;
    }
    holder->curl = curl;
    pthread_mutex_lock(&priv->mutex);
    LIST_INSERT_HEAD(&priv->curls, holder, link);
    pthread_mutex_unlock(&priv->mutex);
}


/* Other functions */
void
http_io_list_prepper(CURL *curl, struct http_io *io)
{
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_io_curl_list_reader);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, io);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, io->headers);
    curl_easy_setopt(curl, CURLOPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, (long)1);
}

void
http_io_head_prepper(CURL *curl, struct http_io *io)
{
    memset(&io->bufs, 0, sizeof(io->bufs));
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_io_curl_reader);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, io);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, http_io_curl_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, io);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, io->headers);
}

void
http_io_read_prepper(CURL *curl, struct http_io *io)
{
    memset(&io->bufs, 0, sizeof(io->bufs));
    io->bufs.rdremain = io->buf_size;
    io->bufs.rddata = io->dest;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_io_curl_reader);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, io);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)io->buf_size);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, io->headers);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, http_io_curl_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, io);
    curl_easy_setopt(curl, CURLOPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, (long)0);
}

void
http_io_write_prepper(CURL *curl, struct http_io *io)
{
    memset(&io->bufs, 0, sizeof(io->bufs));
    if (io->src != NULL) {
        io->bufs.wrremain = io->buf_size;
        io->bufs.wrdata = io->src;
    }
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, http_io_curl_writer);
    curl_easy_setopt(curl, CURLOPT_READDATA, io);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_io_curl_reader);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, io);
    if (io->src != NULL) {
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)io->buf_size);
    }
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, io->method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, io->headers);
}

size_t
http_io_curl_list_reader(const void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct http_io *const io = (struct http_io *)stream;
    size_t total = size * nmemb;

    if (io->xml_error != XML_ERROR_NONE)
        return total;
    if (XML_Parse(io->xml, ptr, total, 0) != XML_STATUS_OK) {
        io->xml_error = XML_GetErrorCode(io->xml);
        io->xml_error_line = XML_GetCurrentLineNumber(io->xml);
        io->xml_error_column = XML_GetCurrentColumnNumber(io->xml);
    }
    return total;
}

/* 
 * Authentication functions
 */
int update_credentials(struct http_io_private *const priv){
 
    struct http_io_conf *const config = priv->config;
  
    return ( (*config->update_auth_threads)(priv) );
}


void * 
update_credentials_main(void *arg)
{
    struct http_io_private *const priv = arg;
    struct http_io_conf *const config = priv->config;
    int r = 0;

    while (!priv->shutting_down) {

        // Sleep for five minutes
        sleep(300);

        // Shutting down?
        if (priv->shutting_down)
            break;

        // Attempt to update credentials
        if ((r = ( (*config->update_auth_threads)(priv) )) != 0)
            return NULL;
    }
    // Done
    return NULL;
}

/*
 * Initialize all http parameters which will be used in http requests to perform cloudbacker_store functions,
 * as per the storage type.
 */
static void 
http_io_init(struct http_io_private *priv)
{
    struct http_io_conf *const config = priv->config;
    (*config->set_http_io_params)(config);
}
