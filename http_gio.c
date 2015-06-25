
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
#include "s3b_http_io.h"
#include "http_gio.h"

/*
Initialize storage specific function pointers
*/

struct cloudbacker_store *
http_io_create(struct http_io_conf *config)
{
    int r;
    struct cloudbacker_store *backerstore;
 
    /* Initialize structures */
    if ((backerstore = calloc(1, sizeof(*backerstore))) == NULL) {
        r = errno;
        (*config->log)(LOG_ERR, "http_io creation failed: %s", strerror(r));
        return NULL;
    }   

    if(config->storage_prefix == GS_STORAGE){
        // backerstore = gsb_http_io_create(config);
    }
    else if(config->storage_prefix == S3_STORAGE){
        backerstore = s3b_http_io_create(config);
    }
    return backerstore;
}

/*int
http_io_parse_block(struct http_io_conf *config, const char *name, cb_block_t *block_nump){
    int r = 0;
    if(config->storage_prefix == GS_STORAGE){
        // r = gsb_http_io_parse_block(config, name, *block_nump);
    }
    else if(config->storage_prefix == S3_STORAGE){
        r = s3b_http_io_parse_block(config, name, *block_nump);
    }

    return r;
}
void
http_io_get_stats(struct cloudbacker_store *backerstore, struct http_io_stats *stats){

    if(config->storage_prefix == GS_STORAGE){
       gsb_http_io_get_stats(backerstore, stats);
    }
    else if(config->storage_prefix == S3_STORAGE){
       s3b_http_io_get_stats(backerstore, stats);
    }
}*/
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

/* CURL callbacks */

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

/* */
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


int
http_io_strcasecmp_ptr(const void *const ptr1, const void *const ptr2)
{
    const char *const str1 = *(const char *const *)ptr1;
    const char *const str2 = *(const char *const *)ptr2;

    return strcasecmp(str1, str2);
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
http_io_openssl_locker(int mode, int i, const char *file, int line)
{
    if ((mode & CRYPTO_LOCK) != 0)
        pthread_mutex_lock(&openssl_locks[i]);
    else
        pthread_mutex_unlock(&openssl_locks[i]);
}

u_long
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
