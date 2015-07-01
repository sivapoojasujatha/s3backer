
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
#include "block_part.h"
#include "http_gio.h"
#include "s3b_http_io.h"

/* S3-specific HTTP definitions */
#define FILE_SIZE_HEADER            "x-amz-meta-s3backer-filesize"
#define BLOCK_SIZE_HEADER           "x-amz-meta-s3backer-blocksize"
#define HMAC_HEADER                 "x-amz-meta-cloudbacker.hmac"
#define ACL_HEADER                  "x-amz-acl"
#define CONTENT_SHA256_HEADER       "x-amz-content-sha256"
#define STORAGE_CLASS_HEADER        "x-amz-storage-class"

/* `x-amz-date' header formats */
#define AWS_DATE_HEADER             "x-amz-date"
#define AWS_DATE_BUF_FMT            "%Y%m%dT%H%M%SZ"

/* AWS signature */
#define SIGNATURE_ALGORITHM         "AWS4-HMAC-SHA256"
#define ACCESS_KEY_PREFIX           "AWS4"
#define S3_SERVICE_NAME             "s3"
#define SIGNATURE_TERMINATOR        "aws4_request"
#define SECURITY_TOKEN_HEADER       "x-amz-security-token"

/* EC2 IAM info URL */
#define EC2_IAM_META_DATA_URLBASE   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
#define EC2_IAM_META_DATA_ACCESSID  "AccessKeyId"
#define EC2_IAM_META_DATA_ACCESSKEY "SecretAccessKey"
#define EC2_IAM_META_DATA_TOKEN     "Token"


/*
 * HTTP-based implementation of cloudbacker_store.
 *
 * This implementation does no caching or consistency checking.
 */

/* cloudbacker_store functions */
static int s3b_http_io_meta_data(struct cloudbacker_store *backerstore, off_t *file_sizep, u_int *block_sizep);
static int s3b_http_io_set_mounted(struct cloudbacker_store *backerstore, int *old_valuep, int new_value);
static int s3b_http_io_read_block(struct cloudbacker_store *backerstore, cb_block_t block_num, void *dest,
  u_char *actual_md5, const u_char *expect_md5, int strict);
static int s3b_http_io_write_block(struct cloudbacker_store *backerstore, cb_block_t block_num, const void *src, u_char *md5,
  check_cancel_t *check_cancel, void *check_cancel_arg);
static int s3b_http_io_read_block_part(struct cloudbacker_store *backerstore, cb_block_t block_num, u_int off, u_int len, void *dest);
static int s3b_http_io_write_block_part(struct cloudbacker_store *backerstore, cb_block_t block_num, u_int off, u_int len, const void *src);
static int s3b_http_io_list_blocks(struct cloudbacker_store *backerstore, block_list_func_t *callback, void *arg);
static int s3b_http_io_flush(struct cloudbacker_store *backerstore);
static void s3b_http_io_destroy(struct cloudbacker_store *backerstore);

/* S3 REST API functions */
static void s3b_http_io_get_block_url(char *buf, size_t bufsiz, struct http_io_conf *config, cb_block_t block_num);
static void s3b_http_io_get_mounted_flag_url(char *buf, size_t bufsiz, struct http_io_conf *config);
static int s3b_http_io_add_auth(struct http_io_private *priv, struct http_io *io, time_t now, const void *payload, size_t plen);
static int s3b_http_io_add_auth2(struct http_io_private *priv, struct http_io *io, time_t now, const void *payload, size_t plen);
static int s3b_http_io_add_auth4(struct http_io_private *priv, struct http_io *io, time_t now, const void *payload, size_t plen);

/* EC2 IAM thread */
static void *update_iam_credentials_main(void *arg);
static int update_iam_credentials(struct http_io_private *priv);

/* Misc */
static void file_size_parser(char *buf, struct http_io *io);
static void block_size_parser(char *buf, struct http_io *io);
static void etag_parser(char *buf, struct http_io *io);
static void hmac_parser(char *buf, struct http_io *io);
static void encoding_parser(char *buf, struct http_io *io);

/* NULL-terminated vector of header parsers for S3 */
static header_parser_t s3b_header_parser[] = {
  file_size_parser, block_size_parser, etag_parser,
  hmac_parser, encoding_parser, NULL
};

/*
 * Constructor
 *
 * On error, returns NULL and sets `errno'.
 */
struct cloudbacker_store *
s3b_http_io_create(struct http_io_conf *config)
{
    struct cloudbacker_store *backerstore;
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
    if ((backerstore = calloc(1, sizeof(*backerstore))) == NULL) {
        r = errno;
        goto fail0;
    }
    backerstore->meta_data = s3b_http_io_meta_data;
    backerstore->set_mounted = s3b_http_io_set_mounted;
    backerstore->read_block = s3b_http_io_read_block;
    backerstore->write_block = s3b_http_io_write_block;
    backerstore->read_block_part = s3b_http_io_read_block_part;
    backerstore->write_block_part = s3b_http_io_write_block_part;
    backerstore->list_blocks = s3b_http_io_list_blocks;
    backerstore->flush = s3b_http_io_flush;
    backerstore->destroy = s3b_http_io_destroy;
    if ((priv = calloc(1, sizeof(*priv))) == NULL) {
        r = errno;
        goto fail1;
    }
    priv->config = config;
    if ((r = pthread_mutex_init(&priv->mutex, NULL)) != 0)
        goto fail2;
    LIST_INIT(&priv->curls);
    backerstore->data = priv;

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

    /* Initialize IAM credentials and start updater thread */
    if (config->http_s3b.auth.u.s3.ec2iam_role != NULL) {
        if ((r = update_iam_credentials(priv)) != 0)
            goto fail5;
        if ((r = pthread_create(&priv->auth_thread, NULL, update_iam_credentials_main, priv)) != 0)
            goto fail5;
    }

    /* Take ownership of non-zero block bitmap */
    priv->non_zero = config->nonzero_bitmap;
    config->nonzero_bitmap = NULL;

    /* Done */
    return backerstore;

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
    free(backerstore);
fail0:
    (*config->log)(LOG_ERR, "http_io creation failed: %s", strerror(r));
    errno = r;
    return NULL;
}

/*
 * Destructor
 */
void
s3b_http_io_destroy(struct cloudbacker_store *const s3b)
{
    struct http_io_private *const priv = s3b->data;
    struct http_io_conf *const config = priv->config;
    struct curl_holder *holder;
    int r;

    /* Shut down IAM thread */
    priv->shutting_down = 1;
    if (config->http_s3b.auth.u.s3.ec2iam_role != NULL) {
        (*config->log)(LOG_DEBUG, "waiting for EC2 IAM thread to shutdown");
        if ((r = pthread_cancel(priv->auth_thread)) != 0)
            (*config->log)(LOG_ERR, "pthread_cancel: %s", strerror(r));
        if ((r = pthread_join(priv->auth_thread, NULL)) != 0)
            (*config->log)(LOG_ERR, "pthread_join: %s", strerror(r));
        else
            (*config->log)(LOG_DEBUG, "EC2 IAM thread successfully shutdown");
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
    free(s3b);
}

int
s3b_http_io_flush(struct cloudbacker_store *const s3b)
{
    return 0;
}



/*
 * Add date header based on supplied time.
 */
static void
http_io_add_date(struct http_io_private *const priv, struct http_io *const io, time_t now)
{
    struct http_io_conf *const config = priv->config;
    char buf[DATE_BUF_SIZE];
    struct tm tm;

    if (strcmp(config->http_s3b.auth.u.s3.authVersion, AUTH_VERSION_AWS2) == 0) {
        strftime(buf, sizeof(buf), HTTP_DATE_BUF_FMT, gmtime_r(&now, &tm));
        io->headers = http_io_add_header(io->headers, "%s: %s", HTTP_DATE_HEADER, buf);
    } else {
        strftime(buf, sizeof(buf), AWS_DATE_BUF_FMT, gmtime_r(&now, &tm));
        io->headers = http_io_add_header(io->headers, "%s: %s", AWS_DATE_HEADER, buf);
    }
}

int
s3b_http_io_list_blocks(struct cloudbacker_store *backerstore, block_list_func_t *callback, void *arg)
{
    struct http_io_private *const priv = backerstore->data;
    struct http_io_conf *const config = priv->config;
    char marker[sizeof("&marker=") + strlen(config->prefix) + CLOUDBACKER_BLOCK_NUM_DIGITS + 1];
    char urlbuf[URL_BUF_SIZE(config) + sizeof(marker) + 32];
    struct http_io io;
    int r;

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = s3b_header_parser;
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
    io.xml_text_max = strlen(config->prefix) + CLOUDBACKER_BLOCK_NUM_DIGITS + 10;
    if ((io.xml_text = malloc(io.xml_text_max + 1)) == NULL) {
        (*config->log)(LOG_ERR, "malloc: %s", strerror(errno));
        goto oom;
    }
    if ((io.xml_path = calloc(1, 1)) == NULL) {
        (*config->log)(LOG_ERR, "calloc: %s", strerror(errno));
        goto oom;
    }

    /* List blocks */
    do {
        const time_t now = time(NULL);

        /* Reset XML parser state */
        XML_ParserReset(io.xml, NULL);
        XML_SetUserData(io.xml, &io);
        XML_SetElementHandler(io.xml, http_io_list_elem_start, http_io_list_elem_end);
        XML_SetCharacterDataHandler(io.xml, http_io_list_text);

        /* Format URL */
        snprintf(urlbuf, sizeof(urlbuf), "%s%s?", config->baseURL, config->vhost ? "" : config->bucket);

        /* Add URL parameters (note: must be in "canonical query string" format for proper authentication) */
        if (io.list_truncated) {
            snprintf(urlbuf + strlen(urlbuf), sizeof(urlbuf) - strlen(urlbuf), "%s=%s%0*jx&",
              LIST_PARAM_MARKER, config->prefix, CLOUDBACKER_BLOCK_NUM_DIGITS, (uintmax_t)io.last_block);
        }
        snprintf(urlbuf + strlen(urlbuf), sizeof(urlbuf) - strlen(urlbuf), "%s=%u", LIST_PARAM_MAX_KEYS, LIST_BLOCKS_CHUNK);
        snprintf(urlbuf + strlen(urlbuf), sizeof(urlbuf) - strlen(urlbuf), "&%s=%s", LIST_PARAM_PREFIX, config->prefix);

        /* Add Date header */
        http_io_add_date(priv, &io, now);

        /* Add Authorization header */
        if ((r = s3b_http_io_add_auth(priv, &io, now, NULL, 0)) != 0)
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

static int
s3b_http_io_meta_data(struct cloudbacker_store *backerstore, off_t *file_sizep, u_int *block_sizep)
{
    struct http_io_private *const priv = backerstore->data;
    struct http_io_conf *const config = priv->config;
    char urlbuf[URL_BUF_SIZE(config)];
    const time_t now = time(NULL);
    struct http_io io;
    int r;

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = s3b_header_parser;
    io.url = urlbuf;
    io.method = HTTP_HEAD;

    /* Construct URL for the first block */
    s3b_http_io_get_block_url(urlbuf, sizeof(urlbuf), config, 0);

    /* Add Date header */
    http_io_add_date(priv, &io, now);

    /* Add Authorization header */
    if ((r = s3b_http_io_add_auth(priv, &io, now, NULL, 0)) != 0)
        goto done;

    /* Perform operation */
    if ((r = http_io_perform_io(priv, &io, http_io_head_prepper)) != 0)
        goto done;

    /* Extract filesystem sizing information */
    if (io.file_size == 0 || io.block_size == 0) {
        r = ENOENT;
        goto done;
    }
    *file_sizep = (off_t)io.file_size;
    *block_sizep = io.block_size;

done:
    /*  Clean up */
    curl_slist_free_all(io.headers);
    return r;
}

static int
s3b_http_io_set_mounted(struct cloudbacker_store *backerstore, int *old_valuep, int new_value)
{
    struct http_io_private *const priv = backerstore->data;
    struct http_io_conf *const config = priv->config;
    char urlbuf[URL_BUF_SIZE(config) + sizeof(MOUNTED_FLAG)];
    const time_t now = time(NULL);
    struct http_io io;
    int r = 0;

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = s3b_header_parser;
    io.url = urlbuf;
    io.method = HTTP_HEAD;

    /* Construct URL for the mounted flag */
    s3b_http_io_get_mounted_flag_url(urlbuf, sizeof(urlbuf), config);

    /* Get old value */
    if (old_valuep != NULL) {

        /* Add Date header */
        http_io_add_date(priv, &io, now);

        /* Add Authorization header */
        if ((r = s3b_http_io_add_auth(priv, &io, now, NULL, 0)) != 0)
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
        memset(content, 0, sizeof(content));
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
            gethostname(content, sizeof(content - 1));       
            content[sizeof(content) - 1] = '\0';
            strftime(content + strlen(content), sizeof(content) - strlen(content), "\n" AWS_DATE_BUF_FMT "\n", gmtime_r(&now, &tm));
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
            io.headers = http_io_add_header(io.headers, "%s: %s", ACL_HEADER, config->http_s3b.auth.u.s3.accessType);

        /* Add storage class header (if needed) */
        if (config->rrs)
            io.headers = http_io_add_header(io.headers, "%s: %s", STORAGE_CLASS_HEADER, SCLASS_REDUCED_REDUNDANCY);

        /* Add Authorization header */
        if ((r = s3b_http_io_add_auth(priv, &io, now, io.src, io.buf_size)) != 0)
            goto done;

        /* Perform operation to set or clear mounted flag */
        r = http_io_perform_io(priv, &io, http_io_write_prepper);
    }

done:
    /*  Clean up */
    curl_slist_free_all(io.headers);
    return r;
}

static void
http_io_iamcreds_prepper(CURL *curl, struct http_io *io)
{
    memset(&io->bufs, 0, sizeof(io->bufs));
    io->bufs.rdremain = io->buf_size;
    io->bufs.rddata = io->dest;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_io_curl_reader);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, io);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)io->buf_size);
    curl_easy_setopt(curl, CURLOPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, (long)0);
}

static int
update_iam_credentials(struct http_io_private *const priv)
{
    struct http_io_conf *const config = priv->config;
    char urlbuf[sizeof(EC2_IAM_META_DATA_URLBASE) + 128];
    struct http_io io;
    char buf[2048] = { '\0' };
    char *access_id = NULL;
    char *access_key = NULL;
    char *iam_token = NULL;
    size_t buflen;
    int r;

    /* Build URL */
    snprintf(urlbuf, sizeof(urlbuf), "%s%s", EC2_IAM_META_DATA_URLBASE, config->http_s3b.auth.u.s3.ec2iam_role);

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = s3b_header_parser;
    io.url = urlbuf;
    io.method = HTTP_GET;
    io.dest = buf;
    io.buf_size = sizeof(buf);

    /* Perform operation */
    (*config->log)(LOG_INFO, "acquiring EC2 IAM credentials from %s", io.url);
    if ((r = http_io_perform_io(priv, &io, http_io_iamcreds_prepper)) != 0) {
        (*config->log)(LOG_ERR, "failed to acquire EC2 IAM credentials from %s: %s", io.url, strerror(r));
        return r;
    }

    /* Determine how many bytes we read */
    buflen = io.buf_size - io.bufs.rdremain;
    if (buflen > sizeof(buf) - 1)
        buflen = sizeof(buf) - 1;
    buf[buflen] = '\0';

    /* Find credentials in JSON response */
    if ((access_id = parse_json_field(priv, buf, EC2_IAM_META_DATA_ACCESSID)) == NULL
      || (access_key = parse_json_field(priv, buf, EC2_IAM_META_DATA_ACCESSKEY)) == NULL
      || (iam_token = parse_json_field(priv, buf, EC2_IAM_META_DATA_TOKEN)) == NULL) {
        (*config->log)(LOG_ERR, "failed to extract EC2 IAM credentials from response: %s", strerror(errno));
        free(access_id);
        free(access_key);
        return EINVAL;
    }

    /* Update credentials */
    pthread_mutex_lock(&priv->mutex);
    free(config->http_s3b.auth.u.s3.accessId);
    free(config->http_s3b.auth.u.s3.accessKey);
    free(config->http_s3b.auth.u.s3.iam_token);
    config->http_s3b.auth.u.s3.accessId = access_id;
    config->http_s3b.auth.u.s3.accessKey = access_key;
    config->http_s3b.auth.u.s3.iam_token = iam_token;
    pthread_mutex_unlock(&priv->mutex);
    (*config->log)(LOG_INFO, "successfully updated EC2 IAM credentials from %s", io.url);

    /* Done */
    return 0;
}

static void *
update_iam_credentials_main(void *arg)
{
    struct http_io_private *const priv = arg;

    while (!priv->shutting_down) {

        // Sleep for five minutes
        sleep(300);

        // Shutting down?
        if (priv->shutting_down)
            break;

        // Attempt to update credentials
        update_iam_credentials(priv);
    }

    // Done
    return NULL;
}

static int
s3b_http_io_read_block(struct cloudbacker_store *const s3b, cb_block_t block_num, void *dest,
  u_char *actual_md5, const u_char *expect_md5, int strict)
{
    struct http_io_private *const priv = s3b->data;
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
        if ((priv->non_zero[word] & bit) == 0) {
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
    io.header_parser = s3b_header_parser;
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
    s3b_http_io_get_block_url(urlbuf, sizeof(urlbuf), config, block_num);

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
    if ((r = s3b_http_io_add_auth(priv, &io, now, NULL, 0)) != 0)
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
                  CLOUDBACKER_BLOCK_NUM_DIGITS, (uintmax_t)block_num, block_cipher);
                r = EIO;
                break;
            }

            /* Verify encryption type */
            if (strcasecmp(block_cipher, EVP_CIPHER_name(priv->cipher)) != 0) {
                (*config->log)(LOG_ERR, "block %0*jx was encrypted using `%s' but `%s' encryption is configured",
                  CLOUDBACKER_BLOCK_NUM_DIGITS, (uintmax_t)block_num, block_cipher, EVP_CIPHER_name(priv->cipher));
                r = EIO;
                break;
            }

            /* Verify block's signature */
            if (memcmp(io.hmac, zero_hmac, sizeof(io.hmac)) == 0) {
                (*config->log)(LOG_ERR, "block %0*jx is encrypted, but no signature was found",
                  CLOUDBACKER_BLOCK_NUM_DIGITS, (uintmax_t)block_num);
                r = EIO;
                break;
            }
            http_io_authsig(priv, block_num, io.dest, did_read, hmac);
            if (memcmp(io.hmac, hmac, sizeof(hmac)) != 0) {
                (*config->log)(LOG_ERR, "block %0*jx has an incorrect signature (did you provide the right password?)",
                  CLOUDBACKER_BLOCK_NUM_DIGITS, (uintmax_t)block_num);
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
          CLOUDBACKER_BLOCK_NUM_DIGITS, (uintmax_t)block_num, layer);
        r = EIO;
        break;
    }

    /* Check for required encryption */
    if (r == 0 && config->encryption != NULL && !encrypted) {
        (*config->log)(LOG_ERR, "block %0*jx was supposed to be encrypted but wasn't", CLOUDBACKER_BLOCK_NUM_DIGITS, (uintmax_t)block_num);
        r = EIO;
    }

    /* Check for wrong length read */
    if (r == 0 && did_read != config->block_size) {
        (*config->log)(LOG_ERR, "read of block %0*jx returned %lu != %lu bytes",
          CLOUDBACKER_BLOCK_NUM_DIGITS, (uintmax_t)block_num, (u_long)did_read, (u_long)config->block_size);
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
 * Write block if src != NULL, otherwise delete block.
 */
static int
s3b_http_io_write_block(struct cloudbacker_store *const s3b, cb_block_t block_num, const void *src, u_char *caller_md5,
  check_cancel_t *check_cancel, void *check_cancel_arg)
{
    struct http_io_private *const priv = s3b->data;
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
            if ((priv->non_zero[word] & bit) == 0) {
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
    s3b_http_io_get_block_url(urlbuf, sizeof(urlbuf), config, block_num);

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
        io.headers = http_io_add_header(io.headers, "%s: %s", ACL_HEADER, config->http_s3b.auth.u.s3.accessType);

    /* Add file size meta-data to zero'th block */
    if (src != NULL && block_num == 0) {
        io.headers = http_io_add_header(io.headers, "%s: %u", BLOCK_SIZE_HEADER, config->block_size);
        io.headers = http_io_add_header(io.headers, "%s: %ju",
          FILE_SIZE_HEADER, (uintmax_t)(config->block_size * config->num_blocks));
    }

    /* Add signature header (if encrypting) */
    if (src != NULL && config->encryption != NULL)
        io.headers = http_io_add_header(io.headers, "%s: \"%s\"", HMAC_HEADER, hmacbuf);

    /* Add storage class header (if needed) */
    if (config->rrs)
        io.headers = http_io_add_header(io.headers, "%s: %s", STORAGE_CLASS_HEADER, SCLASS_REDUCED_REDUNDANCY);

    /* Add Authorization header */
    if ((r = s3b_http_io_add_auth(priv, &io, now, io.src, io.buf_size)) != 0)
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
s3b_http_io_read_block_part(struct cloudbacker_store *backerstore, cb_block_t block_num, u_int off, u_int len, void *dest)
{
    struct http_io_private *const priv = backerstore->data;
    struct http_io_conf *const config = priv->config;

    return block_part_read_block_part(backerstore, block_num, config->block_size, off, len, dest);
}

static int
s3b_http_io_write_block_part(struct cloudbacker_store *backerstore, cb_block_t block_num, u_int off, u_int len, const void *src)
{
    struct http_io_private *const priv = backerstore->data;
    struct http_io_conf *const config = priv->config;

    return block_part_write_block_part(backerstore, block_num, config->block_size, off, len, src);
}


/*
 * Compute S3 authorization hash using secret access key and add Authorization and SHA256 hash headers.
 *
 * Note: headers must be unique and not wrapped.
 */
static int
s3b_http_io_add_auth(struct http_io_private *priv, struct http_io *const io, time_t now, const void *payload, size_t plen)
{
    const struct http_io_conf *const config = priv->config;

    /* Anything to do? */
    if (config->http_s3b.auth.u.s3.accessId == NULL)
        return 0;

    /* Which auth version? */
    if (strcmp(config->http_s3b.auth.u.s3.authVersion, AUTH_VERSION_AWS2) == 0)
        return s3b_http_io_add_auth2(priv, io, now, payload, plen);
    if (strcmp(config->http_s3b.auth.u.s3.authVersion, AUTH_VERSION_AWS4) == 0)
        return s3b_http_io_add_auth4(priv, io, now, payload, plen);

    /* Oops */
    return EINVAL;
}

/**
 * AWS verison 2 authentication
 */
static int
s3b_http_io_add_auth2(struct http_io_private *priv, struct http_io *const io, time_t now, const void *payload, size_t plen)
{
    const struct http_io_conf *const config = priv->config;
    const struct curl_slist *header;
    u_char hmac[SHA_DIGEST_LENGTH];
    const char *resource;
    char **amz_hdrs = NULL;
    char access_id[128];
    char access_key[128];
    char authbuf[200];
#if DEBUG_AUTHENTICATION
    char sigbuf[1024];
    char hmac_buf[EVP_MAX_MD_SIZE * 2 + 1];
#else
    char sigbuf[1];
#endif
    int num_amz_hdrs;
    const char *qmark;
    size_t resource_len;
    u_int hmac_len;
    HMAC_CTX hmac_ctx;
    int i;
    int r;

    /* Snapshot current credentials */
    pthread_mutex_lock(&priv->mutex);
    snprintf(access_id, sizeof(access_id), "%s", config->http_s3b.auth.u.s3.accessId);
    snprintf(access_key, sizeof(access_key), "%s", config->http_s3b.auth.u.s3.accessKey);
    pthread_mutex_unlock(&priv->mutex);

    /* Initialize HMAC */
    HMAC_CTX_init(&hmac_ctx);
    HMAC_Init_ex(&hmac_ctx, access_key, strlen(access_key), EVP_sha1(), NULL);

#if DEBUG_AUTHENTICATION
    *sigbuf = '\0';
#endif

    /* Sign initial stuff */
    HMAC_Update(&hmac_ctx, (const u_char *)io->method, strlen(io->method));
    HMAC_Update(&hmac_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%s\n", io->method);
#endif
    update_hmac_from_header(&hmac_ctx, io, MD5_HEADER, 1, sigbuf, sizeof(sigbuf));
    update_hmac_from_header(&hmac_ctx, io, CTYPE_HEADER, 1, sigbuf, sizeof(sigbuf));
    update_hmac_from_header(&hmac_ctx, io, HTTP_DATE_HEADER, 1, sigbuf, sizeof(sigbuf));

    /* Get x-amz headers sorted by name */
    for (header = io->headers, num_amz_hdrs = 0; header != NULL; header = header->next) {
        if (strncmp(header->data, "x-amz", 5) == 0)
            num_amz_hdrs++;
    }
    if ((amz_hdrs = malloc(num_amz_hdrs * sizeof(*amz_hdrs))) == NULL) {
        r = errno;
        goto fail;
    }
    for (header = io->headers, i = 0; header != NULL; header = header->next) {
        if (strncmp(header->data, "x-amz", 5) == 0)
            amz_hdrs[i++] = header->data;
    }
    assert(i == num_amz_hdrs);
    qsort(amz_hdrs, num_amz_hdrs, sizeof(*amz_hdrs), http_io_strcasecmp_ptr);

    /* Sign x-amz headers (in sorted order) */
    for (i = 0; i < num_amz_hdrs; i++)
        update_hmac_from_header(&hmac_ctx, io, amz_hdrs[i], 0, sigbuf, sizeof(sigbuf));

    /* Get resource */
    resource = config->vhost ? io->url + strlen(config->baseURL) - 1 : io->url + strlen(config->baseURL) + strlen(config->bucket);
    resource_len = (qmark = strchr(resource, '?')) != NULL ? qmark - resource : strlen(resource);

    /* Sign final stuff */
    HMAC_Update(&hmac_ctx, (const u_char *)"/", 1);
    HMAC_Update(&hmac_ctx, (const u_char *)config->bucket, strlen(config->bucket));
    HMAC_Update(&hmac_ctx, (const u_char *)resource, resource_len);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "/%s%.*s", config->bucket, resource_len, resource);
#endif

    /* Finish up */
    HMAC_Final(&hmac_ctx, hmac, &hmac_len);
    assert(hmac_len == SHA_DIGEST_LENGTH);
    HMAC_CTX_cleanup(&hmac_ctx);

    /* Base64-encode result */
    http_io_base64_encode(authbuf, sizeof(authbuf), hmac, hmac_len);

#if DEBUG_AUTHENTICATION
    (*config->log)(LOG_DEBUG, "auth: string to sign:\n%s", sigbuf);
    http_io_prhex(hmac_buf, hmac, hmac_len);
    (*config->log)(LOG_DEBUG, "auth: signature hmac = %s", hmac_buf);
    (*config->log)(LOG_DEBUG, "auth: signature hmac base64 = %s", authbuf);
#endif

    /* Add auth header */
    io->headers = http_io_add_header(io->headers, "%s: AWS %s:%s", AUTH_HEADER, access_id, authbuf);

    /* Done */
    r = 0;

fail:
    /* Clean up */
    if (amz_hdrs != NULL)
        free(amz_hdrs);
    HMAC_CTX_cleanup(&hmac_ctx);
    return r;
}

/**
 * AWS verison 4 authentication
 */
static int
s3b_http_io_add_auth4(struct http_io_private *priv, struct http_io *const io, time_t now, const void *payload, size_t plen)
{
    const struct http_io_conf *const config = priv->config;
    u_char payload_hash[EVP_MAX_MD_SIZE];
    u_char creq_hash[EVP_MAX_MD_SIZE];
    u_char hmac[EVP_MAX_MD_SIZE];
    u_int payload_hash_len;
    u_int creq_hash_len;
    u_int hmac_len;
    char payload_hash_buf[EVP_MAX_MD_SIZE * 2 + 1];
    char creq_hash_buf[EVP_MAX_MD_SIZE * 2 + 1];
    char hmac_buf[EVP_MAX_MD_SIZE * 2 + 1];
    const struct curl_slist *hdr;
    char **sorted_hdrs = NULL;
    char *header_names = NULL;
    const char *host;
    size_t host_len;
    const char *uripath;
    size_t uripath_len;
    const char *query_params;
    size_t query_params_len;
    u_int header_names_length;
    u_int num_sorted_hdrs;
    EVP_MD_CTX hash_ctx;
    HMAC_CTX hmac_ctx;
#if DEBUG_AUTHENTICATION
    char sigbuf[1024];
#endif
    char hosthdr[128];
    char datebuf[DATE_BUF_SIZE];
    char access_id[128];
    char access_key[128];
    char iam_token[1024];
    struct tm tm;
    char *p;
    int r;
    int i;

    /* Initialize */
    EVP_MD_CTX_init(&hash_ctx);
    HMAC_CTX_init(&hmac_ctx);

    /* Snapshot current credentials */
    pthread_mutex_lock(&priv->mutex);
    snprintf(access_id, sizeof(access_id), "%s", config->http_s3b.auth.u.s3.accessId);
    snprintf(access_key, sizeof(access_key), "%s%s", ACCESS_KEY_PREFIX, config->http_s3b.auth.u.s3.accessKey);
    snprintf(iam_token, sizeof(iam_token), "%s", config->http_s3b.auth.u.s3.iam_token != NULL ? config->http_s3b.auth.u.s3.iam_token : "");
    pthread_mutex_unlock(&priv->mutex);

    /* Extract host, URI path, and query parameters from URL */
    if ((p = strchr(io->url, ':')) == NULL || *++p != '/' || *++p != '/'
      || (host = p + 1) == NULL || (uripath = strchr(host, '/')) == NULL) {
        r = EINVAL;
        goto fail;
    }
    host_len = uripath - host;
    if ((p = strchr(uripath, '?')) != NULL) {
        uripath_len = p - uripath;
        query_params = p + 1;
        query_params_len = strlen(query_params);
    } else {
        uripath_len = strlen(uripath);
        query_params = NULL;
        query_params_len = 0;
    }

    /* Format date */
    strftime(datebuf, sizeof(datebuf), AWS_DATE_BUF_FMT, gmtime_r(&now, &tm));

/****** Hash Payload and Add Header ******/

    EVP_DigestInit_ex(&hash_ctx, EVP_sha256(), NULL);
    if (payload != NULL)
        EVP_DigestUpdate(&hash_ctx, payload, plen);
    EVP_DigestFinal_ex(&hash_ctx, payload_hash, &payload_hash_len);
    http_io_prhex(payload_hash_buf, payload_hash, payload_hash_len);

    io->headers = http_io_add_header(io->headers, "%s: %s", CONTENT_SHA256_HEADER, payload_hash_buf);

/****** Add IAM security token header (if any) ******/

    if (*iam_token != '\0')
        io->headers = http_io_add_header(io->headers, "%s: %s", SECURITY_TOKEN_HEADER, iam_token);

/****** Create Hashed Canonical Request ******/

#if DEBUG_AUTHENTICATION
    *sigbuf = '\0';
#endif

    /* Reset hash */
    EVP_DigestInit_ex(&hash_ctx, EVP_sha256(), NULL);

    /* Sort headers by (lowercase) name; add "Host" header manually - special case because cURL adds it, not us */
    snprintf(hosthdr, sizeof(hosthdr), "host:%.*s", (int)host_len, host);
    for (num_sorted_hdrs = 1, hdr = io->headers; hdr != NULL; hdr = hdr->next)
        num_sorted_hdrs++;
    if ((sorted_hdrs = malloc(num_sorted_hdrs * sizeof(*sorted_hdrs))) == NULL) {
        r = errno;
        goto fail;
    }
    sorted_hdrs[0] = hosthdr;
    for (i = 1, hdr = io->headers; hdr != NULL; hdr = hdr->next)
        sorted_hdrs[i++] = hdr->data;
    assert(i == num_sorted_hdrs);
    qsort(sorted_hdrs, num_sorted_hdrs, sizeof(*sorted_hdrs), http_io_strcasecmp_ptr);

    /* Request method */
    EVP_DigestUpdate(&hash_ctx, (const u_char *)io->method, strlen(io->method));
    EVP_DigestUpdate(&hash_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%s\n", io->method);
#endif

    /* Canonical URI */
    EVP_DigestUpdate(&hash_ctx, (const u_char *)uripath, uripath_len);
    EVP_DigestUpdate(&hash_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%.*s\n", (int)uripath_len, uripath);
#endif

    /* Canonical query string */
    EVP_DigestUpdate(&hash_ctx, (const u_char *)query_params, query_params_len);
    EVP_DigestUpdate(&hash_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%.*s\n", (int)query_params_len, query_params);
#endif

    /* Canonical headers */
    header_names_length = 0;
    for (i = 0; i < num_sorted_hdrs; i++) {
        const char *value = sorted_hdrs[i];
        const char *s;
        char lcase;

        s = value;
        do {
            if (*s == '\0') {
                r = EINVAL;
                goto fail;
            }
            lcase = tolower(*s);
            EVP_DigestUpdate(&hash_ctx, (const u_char *)&lcase, 1);
#if DEBUG_AUTHENTICATION
            snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%c", lcase);
#endif
            header_names_length++;
        } while (*s++ != ':');
        while (isspace(*s))
            s++;
        EVP_DigestUpdate(&hash_ctx, (const u_char *)s, strlen(s));
        EVP_DigestUpdate(&hash_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
        snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%s\n", s);
#endif
    }
    EVP_DigestUpdate(&hash_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "\n");
#endif

    /* Signed headers */
    if ((header_names = malloc(header_names_length)) == NULL) {
        r = errno;
        goto fail;
    }
    p = header_names;
    for (i = 0; i < num_sorted_hdrs; i++) {
        const char *value = sorted_hdrs[i];
        const char *s;

        if (p > header_names)
            *p++ = ';';
        for (s = value; *s != '\0' && *s != ':'; s++)
            *p++ = tolower(*s);
    }
    *p++ = '\0';
    assert(p <= header_names + header_names_length);
    EVP_DigestUpdate(&hash_ctx, (const u_char *)header_names, strlen(header_names));
    EVP_DigestUpdate(&hash_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%s\n", header_names);
#endif

    /* Hashed payload */
    EVP_DigestUpdate(&hash_ctx, (const u_char *)payload_hash_buf, strlen(payload_hash_buf));
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%s", payload_hash_buf);
#endif

    /* Get canonical request hash as a string */
    EVP_DigestFinal_ex(&hash_ctx, creq_hash, &creq_hash_len);
    http_io_prhex(creq_hash_buf, creq_hash, creq_hash_len);

#if DEBUG_AUTHENTICATION
    (*config->log)(LOG_DEBUG, "auth: canonical request:\n%s", sigbuf);
    (*config->log)(LOG_DEBUG, "auth: canonical request hash = %s", creq_hash_buf);
#endif

/****** Derive Signing Key ******/

    /* Do nested HMAC's */
    HMAC_Init_ex(&hmac_ctx, access_key, strlen(access_key), EVP_sha256(), NULL);
#if DEBUG_AUTHENTICATION
    (*config->log)(LOG_DEBUG, "auth: access_key = \"%s\"", access_key);
#endif
    HMAC_Update(&hmac_ctx, (const u_char *)datebuf, 8);
    HMAC_Final(&hmac_ctx, hmac, &hmac_len);
    assert(hmac_len <= sizeof(hmac));
#if DEBUG_AUTHENTICATION
    http_io_prhex(hmac_buf, hmac, hmac_len);
    (*config->log)(LOG_DEBUG, "auth: HMAC[%.8s] = %s", datebuf, hmac_buf);
#endif
    HMAC_Init_ex(&hmac_ctx, hmac, hmac_len, EVP_sha256(), NULL);
    HMAC_Update(&hmac_ctx, (const u_char *)config->region, strlen(config->region));
    HMAC_Final(&hmac_ctx, hmac, &hmac_len);
#if DEBUG_AUTHENTICATION
    http_io_prhex(hmac_buf, hmac, hmac_len);
    (*config->log)(LOG_DEBUG, "auth: HMAC[%s] = %s", config->region, hmac_buf);
#endif
    HMAC_Init_ex(&hmac_ctx, hmac, hmac_len, EVP_sha256(), NULL);
    HMAC_Update(&hmac_ctx, (const u_char *)S3_SERVICE_NAME, strlen(S3_SERVICE_NAME));
    HMAC_Final(&hmac_ctx, hmac, &hmac_len);
#if DEBUG_AUTHENTICATION
    http_io_prhex(hmac_buf, hmac, hmac_len);
    (*config->log)(LOG_DEBUG, "auth: HMAC[%s] = %sn", S3_SERVICE_NAME, hmac_buf);
#endif
    HMAC_Init_ex(&hmac_ctx, hmac, hmac_len, EVP_sha256(), NULL);
    HMAC_Update(&hmac_ctx, (const u_char *)SIGNATURE_TERMINATOR, strlen(SIGNATURE_TERMINATOR));
    HMAC_Final(&hmac_ctx, hmac, &hmac_len);
#if DEBUG_AUTHENTICATION
    http_io_prhex(hmac_buf, hmac, hmac_len);
    (*config->log)(LOG_DEBUG, "auth: HMAC[%s] = %s", SIGNATURE_TERMINATOR, hmac_buf);
#endif

/****** Sign the String To Sign ******/

#if DEBUG_AUTHENTICATION
    *sigbuf = '\0';
#endif
    HMAC_Init_ex(&hmac_ctx, hmac, hmac_len, EVP_sha256(), NULL);
    HMAC_Update(&hmac_ctx, (const u_char *)SIGNATURE_ALGORITHM, strlen(SIGNATURE_ALGORITHM));
    HMAC_Update(&hmac_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%s\n", SIGNATURE_ALGORITHM);
#endif
    HMAC_Update(&hmac_ctx, (const u_char *)datebuf, strlen(datebuf));
    HMAC_Update(&hmac_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%s\n", datebuf);
#endif
    HMAC_Update(&hmac_ctx, (const u_char *)datebuf, 8);
    HMAC_Update(&hmac_ctx, (const u_char *)"/", 1);
    HMAC_Update(&hmac_ctx, (const u_char *)config->region, strlen(config->region));
    HMAC_Update(&hmac_ctx, (const u_char *)"/", 1);
    HMAC_Update(&hmac_ctx, (const u_char *)S3_SERVICE_NAME, strlen(S3_SERVICE_NAME));
    HMAC_Update(&hmac_ctx, (const u_char *)"/", 1);
    HMAC_Update(&hmac_ctx, (const u_char *)SIGNATURE_TERMINATOR, strlen(SIGNATURE_TERMINATOR));
    HMAC_Update(&hmac_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%.8s/%s/%s/%s\n",
      datebuf, config->region, S3_SERVICE_NAME, SIGNATURE_TERMINATOR);
#endif
    HMAC_Update(&hmac_ctx, (const u_char *)creq_hash_buf, strlen(creq_hash_buf));
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%s", creq_hash_buf);
#endif
    HMAC_Final(&hmac_ctx, hmac, &hmac_len);
    http_io_prhex(hmac_buf, hmac, hmac_len);

#if DEBUG_AUTHENTICATION
    (*config->log)(LOG_DEBUG, "auth: key to sign:\n%s", sigbuf);
    (*config->log)(LOG_DEBUG, "auth: signature hmac = %s", hmac_buf);
#endif

/****** Add Authorization Header ******/

    io->headers = http_io_add_header(io->headers, "%s: %s Credential=%s/%.8s/%s/%s/%s, SignedHeaders=%s, Signature=%s",
      AUTH_HEADER, SIGNATURE_ALGORITHM, access_id, datebuf, config->region, S3_SERVICE_NAME, SIGNATURE_TERMINATOR,
      header_names, hmac_buf);

    /* Done */
    r = 0;

fail:
    /* Clean up */
    if (sorted_hdrs != NULL)
        free(sorted_hdrs);
    free(header_names);
    EVP_MD_CTX_cleanup(&hash_ctx);
    HMAC_CTX_cleanup(&hmac_ctx);
    return r;
}

/*
 * Create URL for a block, and return pointer to the URL's URI path.
 */

/*
 * Improve S3 name hashing by reversing the bit sequence of the block number
 */
static cb_block_t bit_reverse(cb_block_t block_num)
{
    int nbits = sizeof(cb_block_t) * 8;
    cb_block_t reversed_block_num = (cb_block_t)0;
    int b, ib;

    if (block_num == 0) return block_num;

    for (b = nbits - 1, ib = 0; b >= 0; b--, ib++) {
	unsigned char bit = (block_num & (1 << b)) >> b;
	reversed_block_num |= bit << ib;
    }

    return reversed_block_num;
}

static void
s3b_http_io_get_block_url(char *buf, size_t bufsiz, struct http_io_conf *config, cb_block_t block_num)
{
    int len;

    if (config->vhost)
        len = snprintf(buf, bufsiz, "%s%s%0*jx", config->baseURL, config->prefix, CLOUDBACKER_BLOCK_NUM_DIGITS,
                       (uintmax_t)(bit_reverse(block_num)));
    else {
        len = snprintf(buf, bufsiz, "%s%s/%s%0*jx", config->baseURL,
                       config->bucket, config->prefix, CLOUDBACKER_BLOCK_NUM_DIGITS,
                       (uintmax_t)(bit_reverse(block_num)));
    }
    (void)len;                  /* avoid compiler warning when NDEBUG defined */
    assert(len < bufsiz);
}

/*
 * Create URL for the mounted flag, and return pointer to the URL's path not including any "/bucket" prefix.
 */
static void
s3b_http_io_get_mounted_flag_url(char *buf, size_t bufsiz, struct http_io_conf *config)
{
    int len;

    if (config->vhost)
        len = snprintf(buf, bufsiz, "%s%s%s", config->baseURL, config->prefix, MOUNTED_FLAG);
    else
        len = snprintf(buf, bufsiz, "%s%s/%s%s", config->baseURL, config->bucket, config->prefix, MOUNTED_FLAG);
    (void)len;                  /* avoid compiler warning when NDEBUG defined */
    assert(len < bufsiz);
}

/* Parsers defined */
static void file_size_parser(char *buf, struct http_io *io)
{
    (void)sscanf(buf, FILE_SIZE_HEADER ": %ju", &io->file_size);
}

static void block_size_parser(char *buf, struct http_io *io)
{
    (void)sscanf(buf, BLOCK_SIZE_HEADER ": %u", &io->block_size);
}

static void etag_parser(char *buf, struct http_io *io)
{
    char fmtbuf[64];
    if (strncasecmp(buf, ETAG_HEADER ":", sizeof(ETAG_HEADER)) == 0) {
        char md5buf[MD5_DIGEST_LENGTH * 2 + 1];

        snprintf(fmtbuf, sizeof(fmtbuf), " \"%%%uc\"", MD5_DIGEST_LENGTH * 2);
        if (sscanf(buf + sizeof(ETAG_HEADER), fmtbuf, md5buf) == 1)
            http_io_parse_hex(md5buf, io->md5, MD5_DIGEST_LENGTH);
    }
}

static void hmac_parser(char *buf, struct http_io *io)
{
    char fmtbuf[64];
    if (strncasecmp(buf, HMAC_HEADER ":", sizeof(HMAC_HEADER)) == 0) {
        char hmacbuf[SHA_DIGEST_LENGTH * 2 + 1];

        snprintf(fmtbuf, sizeof(fmtbuf), " \"%%%uc\"", SHA_DIGEST_LENGTH * 2);
        if (sscanf(buf + sizeof(HMAC_HEADER), fmtbuf, hmacbuf) == 1)
            http_io_parse_hex(hmacbuf, io->hmac, SHA_DIGEST_LENGTH);
    }
}

static void encoding_parser(char *buf, struct http_io *io)
{
    if (strncasecmp(buf, CONTENT_ENCODING_HEADER ":", sizeof(CONTENT_ENCODING_HEADER)) == 0) {
        size_t celen;
        char *state;
        char *s;

        *io->content_encoding = '\0';
        for (s = strtok_r(buf + sizeof(CONTENT_ENCODING_HEADER), WHITESPACE ",", &state);
          s != NULL; s = strtok_r(NULL, WHITESPACE ",", &state)) {
            celen = strlen(io->content_encoding);
            snprintf(io->content_encoding + celen, sizeof(io->content_encoding) - celen, "%s%s", celen > 0 ? "," : "", s);
        }
    }
}

