
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

#ifndef HTTT_IO_TRANSPORT_H
#define HTTT_IO_TRANSPORT_H

#include "auth_conf.h"

/* HTTP definitions */
#define HTTP_GET                    "GET"
#define HTTP_PUT                    "PUT"
#define HTTP_DELETE                 "DELETE"
#define HTTP_HEAD                   "HEAD"
#define HTTP_NOT_MODIFIED           304
#define HTTP_UNAUTHORIZED           401
#define HTTP_FORBIDDEN              403
#define HTTP_NOT_FOUND              404
#define HTTP_PRECONDITION_FAILED    412
#define AUTH_HEADER                 "Authorization"
#define CTYPE_HEADER                "Content-Type"
#define CONTENT_LENGTH              "Content-length"
#define CONTENT_ENCODING_HEADER     "Content-Encoding"
#define ETAG_HEADER                 "ETag"
#define CONTENT_ENCODING_DEFLATE    "deflate"
#define CONTENT_ENCODING_ENCRYPT    "encrypt"
#define MD5_HEADER                  "Content-MD5"
#define IF_MATCH_HEADER             "If-Match"
#define IF_NONE_MATCH_HEADER        "If-None-Match"

/* storage class definitions */

/* SCLASS_STANDARD storage class is common for both S3 and GS */
#define SCLASS_STANDARD                "STANDARD"

/* S3 specific storage class definition */
#define SCLASS_S3_REDUCED_REDUNDANCY   "REDUCED_REDUNDANCY"

/* GS specific storage class definition */
#define SCLASS_GS_NEARLINE             "NEARLINE"
#define SCLASS_GS_DRA                  "DURABLE_REDUCED_AVAILABILITY"

/* Upload/download indexes */
#define HTTP_DOWNLOAD       0
#define HTTP_UPLOAD         1

/* MIME type for mounted flag */
#define MOUNTED_FLAG_CONTENT_TYPE       "text/plain"

/* Mounted file object name */
#define MOUNTED_FLAG                    "cloudbacker-mounted"

/* zero filled meta data block name */
#define ZERO_FILLED_META_DATA_BLOCK     "cloudbacker-zerosize-metadata"
 
/* MIME type for blocks */
#define CONTENT_TYPE                    "application/x-cloudbacker-block"

/* HTTP `Date' and `x-amz-date' header formats */
#define HTTP_DATE_HEADER            "Date"
#define HTTP_DATE_BUF_FMT           "%a, %d %b %Y %H:%M:%S GMT"
#define DATE_BUF_SIZE               64

/* Size required for URL buffer */
#define URL_BUF_SIZE(config)        (strlen((config)->baseURL) + strlen((config)->bucket) \
                                      + strlen((config)->prefix) + CB_BLOCK_NUM_DIGITS + 2)

/* Bucket listing API constants */
#define LIST_PARAM_MARKER           "marker"
#define LIST_PARAM_PREFIX           "prefix"
#define LIST_PARAM_MAX_KEYS         "max-keys"

#define LIST_ELEM_LIST_BUCKET_RESLT "ListBucketResult"
#define LIST_ELEM_IS_TRUNCATED      "IsTruncated"
#define LIST_ELEM_CONTENTS          "Contents"
#define LIST_ELEM_KEY               "Key"
#define LIST_TRUE                   "true"
#define LIST_MAX_PATH               (sizeof(LIST_ELEM_LIST_BUCKET_RESLT) \
                                      + sizeof(LIST_ELEM_CONTENTS) \
                                      + sizeof(LIST_ELEM_KEY) + 1)

/* query string parameter to get storage class attribute of bucket */
#define BUCKET_PARAM_STORAGECLASS   "storageClass"

/* How many blocks to list at a time */
#define LIST_BLOCKS_CHUNK           1000

/* PBKDF2 key generation iterations */
#define PBKDF2_ITERATIONS           5000

/* Enable to debug encryption key stuff */
#define DEBUG_ENCRYPTION            0

/* Enable to debug authentication stuff */
#define DEBUG_AUTHENTICATION        0

#define WHITESPACE                  " \t\v\f\r\n"

/* cloudbacker storage prefix */
typedef enum {GS_STORAGE, S3_STORAGE} storage_type;

/* Statistics structure for http_io store */
struct http_io_evst {
    u_int               count;                      // number of occurrences
    double              time;                       // total time taken
};

struct http_io_stats {

    /* Block stats */
    u_int               normal_blocks_read;
    u_int               normal_blocks_written;
    u_int               zero_blocks_read;
    u_int               zero_blocks_written;
    u_int               empty_blocks_read;          // only when nonzero_bitmap != NULL
    u_int               empty_blocks_written;       // only when nonzero_bitmap != NULL

    /* HTTP transfer stats */
    struct http_io_evst http_heads;                 // total successful
    struct http_io_evst http_gets;                  // total successful
    struct http_io_evst http_puts;                  // total successful
    struct http_io_evst http_deletes;               // total successful
    u_int               http_unauthorized;
    u_int               http_forbidden;
    u_int               http_stale;
    u_int               http_verified;
    u_int               http_mismatch;
    u_int               http_5xx_error;
    u_int               http_4xx_error;
    u_int               http_other_error;
    u_int               http_canceled_writes;

    /* CURL stats */
    u_int               curl_handles_created;
    u_int               curl_handles_reused;
    u_int               curl_timeouts;
    u_int               curl_connect_failed;
    u_int               curl_host_unknown;
    u_int               curl_out_of_memory;
    u_int               curl_other_error;

    /* Retry stats */
    u_int               num_retries;
    uint64_t            retry_delay;

    /* Misc */
    u_int               out_of_memory_errors;
};

/* Internal state */
struct curl_holder {
    CURL                        *curl;
    LIST_ENTRY(curl_holder)     link;
};

struct http_io_private {
    struct http_io_conf         *config;
    struct http_io_stats        stats;
    LIST_HEAD(, curl_holder)    curls;
    pthread_mutex_t             mutex;
    u_int                       *non_zero;              // config->nonzero_bitmap is moved to here
    u_int                       non_zero_complete;      // flag to indicate that the non-zero block bitmap
                                                        // has been fully populated by listing existing blocks
    pthread_t                   block_list_thread;      // IAM credentials refresh thread
    pthread_t                   auth_thread;            // IAM credentials refresh thread
    u_char                      shutting_down;

    /* Encryption info */
    const EVP_CIPHER            *cipher;
    u_int                       keylen;                         // length of key and ivkey
    u_char                      key[EVP_MAX_KEY_LENGTH];        // key used to encrypt data
    u_char                      ivkey[EVP_MAX_KEY_LENGTH];      // key used to encrypt block number to get IV for data
};

/* I/O buffers */
struct http_io_bufs {
    size_t      rdremain;
    size_t      wrremain;
    char        *rddata;
    const char  *wrdata;
};

/* List blocks support */
enum {
    HTTP_IO_BITMAP_NONE,
    HTTP_IO_BITMAP_ASYNC,
    HTTP_IO_BITMAP_DONE
};

#define BLOCKS_PER_DOT                  0x100

struct http_list_blocks {
    u_int               *bitmap;
    int         	print_dots;
    pthread_mutex_t     *mutex;
    uintmax_t           count;
    u_int               async;
};

void http_list_blocks_callback(void *arg, cb_block_t block_num);


/* Header parsing */
struct http_io;
typedef void (*header_parser_t)(char *buf, struct http_io *io);

/* I/O state when reading/writing a block */
struct http_io {

    // post data for post request
    char *post_data;

    // I/O buffers
    struct http_io_bufs bufs;

    // NULL-terminated header parser vector
    const header_parser_t       *header_parser;

    // XML parser and bucket listing info
    XML_Parser          xml;                    // XML parser
    int                 xml_error;              // XML parse error (if any)
    int                 xml_error_line;         // XML parse error line
    int                 xml_error_column;       // XML parse error column
    char                *xml_path;              // Current XML path
    char                *xml_text;              // Current XML text
    int                 xml_text_len;           // # chars in 'xml_text' buffer
    int                 xml_text_max;           // max chars in 'xml_text' buffer
    int                 list_truncated;         // returned list was truncated
    cb_block_t          last_block;             // last dirty block listed
    block_list_func_t   *callback_func;         // callback func for listing blocks
    void                *callback_arg;          // callback arg for listing blocks
    struct http_io_conf *config;                // configuration

    // Other info that needs to be passed around
    const char          *method;                // HTTP method
    const char          *url;                   // HTTP URL
    struct curl_slist   *headers;               // HTTP headers
    void                *dest;                  // Block data (when reading)
    const void          *src;                   // Block data (when writing)
    cb_block_t          block_num;              // The block we're reading/writing
    u_int               buf_size;               // Size of data buffer
    u_int               *content_lengthp;       // Returned Content-Length
    uintmax_t           file_size;              // file size from "x-[amz]/[goog]-meta-*backer-filesize"
    u_int               block_size;             // block size from "x-[amz]/[goog]-meta-*backer-blocksize"
    u_int               name_hash;              // object name hashing from "x-[amz]/[goog]-meta-*backer-namehash"
    u_int               compression_level;      // if compression is used or not "x-[amz]/[goog]-meta-*backer-compression_level"   
    u_int               is_encrypted;           // if encrypt flag is used or not "x-[amz]/[goog]-meta-*backer-encryption" 
    char                *encryption_cipher;     // encryption cipher used  "x-[amz]/[goog]-meta-*backer-encryption-cipher"
    u_int               expect_304;             // a verify request; expect a 304 response
    u_char              md5[MD5_DIGEST_LENGTH]; // parsed ETag header
    u_char              hmac[SHA_DIGEST_LENGTH];// parsed "x-[amz]/[goog]-meta-cloudbacker.hmac" header
    char                content_encoding[32];   // received content encoding
    check_cancel_t      *check_cancel;          // write check-for-cancel callback
    void                *check_cancel_arg;      // write check-for-cancel callback argument
    char                *StorageClass;          // get storage class attribute of GS bucket
};

/* http IO meta data parameters structure */
struct http_io_meta_data {

    u_int                       block_size;
    u_int                       name_hash;
    uintmax_t                   file_size;
    off_t                       num_blocks;
    u_int                       compression_level;
    u_int                       is_encrypted;
    char                        *encryption_cipher;
};

/* Generic configuration info structure for http_io store */
struct http_io_conf {
    struct auth_conf          auth;
    struct http_io_parameters *http_io_params;
    struct http_io_meta_data  http_metadata;
    char                *accessId;
    char                *accessKey;
    char                *ec2iam_role;
    char                *bucket;
    const char          *accessType;
    const char          *authVersion;
    const char          *baseURL;
    const char          *region;
    const char          *prefix;
    const char          *user_agent;
    const char          *cacert;
    const char          *password;
    char                *encryption;
    const char          *storageClass;
    cb_block_t          last_block;                 // last dirty block listed
    u_int               maxKeys;
    u_int               key_length;
    u_int               name_hash;
    int                 debug;
    int                 debug_http;
    int                 quiet;
    int                 compress;                   // zlib compression level
    int                 vhost;                      // use virtual host style URL
    int                 storage_prefix;             // GS_STORAGE or S3_STORAGE
    u_int               *nonzero_bitmap;            // is set to NULL by http_io_create()
    u_int               nonzero_bitmap_complete;
    int                 insecure;
    u_int               block_size;
    off_t               num_blocks;
    u_int               timeout;
    u_int               initial_retry_pause;
    u_int               max_retry_pause;
    uintmax_t           max_speed[2];
    log_func_t          *log;
    
    /* http io layer function pointers to invoke storage specific function implementation */
    void (*set_http_io_params)(struct http_io_conf *config);
    void (*destroy_auth_threads)(struct http_io_private *const priv);
    int (*update_auth_threads)(struct http_io_private *const priv);
    int (*authenticate)(struct http_io_private *priv, struct http_io *const io, time_t now, const void *payload, size_t plen);
};

/* http_gio.c */
extern struct cloudbacker_store *http_io_create(struct http_io_conf *config);
extern void http_io_get_stats(struct cloudbacker_store *cb, struct http_io_stats *stats);
extern int http_io_parse_block(struct http_io_conf *config, const char *name, cb_block_t *block_num);


/* CURL prepper function type */
typedef void http_io_curl_prepper_t(CURL *curl, struct http_io *io);

/* Authentication functions */
int update_credentials(struct http_io_private *const priv);
void* update_credentials_main(void *args);
int http_io_add_auth(struct http_io_private *priv, struct http_io *io, time_t now, const void *payload, size_t plen);

/* parse http json response */
char* parse_json_field(struct http_io_private *priv, const char *json, const char *field);

/* Other functions */
http_io_curl_prepper_t http_io_head_prepper;
http_io_curl_prepper_t http_io_read_prepper;
http_io_curl_prepper_t http_io_write_prepper;
http_io_curl_prepper_t http_io_list_prepper;


/* REST API functions */
void http_io_get_block_url(char *buf, size_t bufsiz, struct http_io_conf *config, cb_block_t block_num);
void http_io_get_mounted_flag_url(char *buf, size_t bufsiz, struct http_io_conf *config);
void http_io_get_bucket_url(char *buf, size_t bufsiz, struct http_io_conf *config);
void http_io_get_meta_data_block_url(char *buf, size_t bufsiz, struct http_io_conf *config);

/* Bucket listing functions */
size_t http_io_curl_list_reader(const void *ptr, size_t size, size_t nmemb, void *stream);
void http_io_list_elem_start(void *arg, const XML_Char *name, const XML_Char **atts);
void http_io_list_elem_end(void *arg, const XML_Char *name);
void http_io_list_text(void *arg, const XML_Char *s, int len);

/* HTTP and curl functions */
int http_io_perform_io(struct http_io_private *priv, struct http_io *io, http_io_curl_prepper_t *prepper);
size_t http_io_curl_reader(const void *ptr, size_t size, size_t nmemb, void *stream);
size_t http_io_curl_writer(void *ptr, size_t size, size_t nmemb, void *stream);
size_t http_io_curl_header(void *ptr, size_t size, size_t nmemb, void *stream);
struct curl_slist *http_io_add_header(struct curl_slist *headers, const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)));
void http_io_add_date(struct http_io_private *priv, struct http_io *const io, time_t now);
CURL *http_io_acquire_curl(struct http_io_private *priv, struct http_io *io);
void http_io_release_curl(struct http_io_private *priv, CURL **curlp, int may_cache);

/* encoding, encryption, parsing etc utility functions */
void http_io_base64_encode(char *buf, size_t bufsiz, const void *data, size_t len);
void update_hmac_from_header(HMAC_CTX *ctx, struct http_io *io,
  const char *name, int value_only, char *sigbuf, size_t sigbuflen);
u_int http_io_crypt(struct http_io_private *priv, cb_block_t block_num, int enc, const u_char *src, u_int len, u_char *dst);
void http_io_authsig(struct http_io_private *priv, cb_block_t block_num, const u_char *src, u_int len, u_char *hmac);
int http_io_is_zero_block(const void *data, u_int block_size);
int http_io_parse_hex(const char *str, u_char *buf, u_int nbytes);
void http_io_prhex(char *buf, const u_char *data, size_t len);
int http_io_strcasecmp_ptr(const void *ptr1, const void *ptr2);


/* Parser functions */
void file_size_parser(char *buf, struct http_io *io);
void block_size_parser(char *buf, struct http_io *io);
void name_hash_parser(char *buf, struct http_io *io);
void compression_parser(char *buf, struct http_io *io);
void encryption_parser(char *buf, struct http_io *io);
void encryption_cipher_parser(char *buf, struct http_io *io);
void etag_parser(char *buf, struct http_io *io);
void hmac_parser(char *buf, struct http_io *io);
void encoding_parser(char *buf, struct http_io *io);


#endif
