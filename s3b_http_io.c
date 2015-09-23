
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
#include "s3b_http_io.h"


/* curl functions */
static http_io_curl_prepper_t http_io_iamcreds_prepper;

/* NULL-terminated vector of header parsers */
static header_parser_t s3b_header_parser[] = {
  file_size_parser, block_size_parser, name_hash_parser,
  etag_parser, hmac_parser, encoding_parser, NULL
};

/* Inititalize s3b http io parameters to be used in http IO requests */
void set_http_io_s3b_params(struct http_io_conf *config)
{
    strcpy(config->http_io_params->file_size_header, S3B_FILE_SIZE_HEADER);
    strcpy(config->http_io_params->block_size_header, S3B_BLOCK_SIZE_HEADER);
    config->http_io_params->block_size_headerval = config->block_size;
    strcpy(config->http_io_params->compression_level_header, S3B_COMPRESSION_LEVEL_HEADER);
    strcpy(config->http_io_params->encrypted_header, S3B_ENCRYPTED_HEADER);
    strcpy(config->http_io_params->encryption_cipher_header, S3B_ENCRYPTION_HEADER);
    strcpy(config->http_io_params->name_hash_header, S3B_NAME_HASH_HEADER);
    strcpy(config->http_io_params->HMAC_Header, S3B_HMAC_HEADER);
    strcpy(config->http_io_params->acl_header,S3B_ACL_HEADER);
    strcpy(config->http_io_params->acl_headerval,config->auth.u.s3.accessType);
    strcpy(config->http_io_params->content_sha256_header, S3B_CONTENT_SHA256_HEADER);
    strcpy(config->http_io_params->storage_class_header, S3B_STORAGE_CLASS_HEADER);
    if( strcasecmp(config->storageClass, SCLASS_S3_REDUCED_REDUNDANCY) == 0)
        strcpy(config->http_io_params->storage_class_headerval, SCLASS_S3_REDUCED_REDUNDANCY);
    else
        strcpy(config->http_io_params->storage_class_headerval, SCLASS_STANDARD);
    if (strcasecmp(config->auth.u.s3.authVersion, AUTH_VERSION_AWS2) == 0){
        strcpy(config->http_io_params->date_header, HTTP_DATE_HEADER);
        strcpy(config->http_io_params->date_buf_fmt,HTTP_DATE_BUF_FMT);
    }
    else{
        strcpy(config->http_io_params->date_header,  AWS_DATE_HEADER);
        strcpy(config->http_io_params->date_buf_fmt, AWS_DATE_BUF_FMT);
    }
    strcpy(config->http_io_params->signature_algorithm,S3B_SIGNATURE_ALGORITHM);
    strcpy(config->http_io_params->accessKey_prefix, S3B_ACCESS_KEY_PREFIX);
    strcpy(config->http_io_params->service_name, S3B_SERVICE_NAME);
    strcpy(config->http_io_params->signature_terminator, S3B_SIGNATURE_TERMINATOR);
    strcpy(config->http_io_params->security_token_header, S3B_SECURITY_TOKEN_HEADER);
    strcpy(config->http_io_params->ec2_iam_meta_data_urlbase, S3B_EC2_IAM_META_DATA_URLBASE);
    strcpy(config->http_io_params->ec2_iam_meta_data_accessID, S3B_EC2_IAM_META_DATA_ACCESSID);
    strcpy(config->http_io_params->ec2_iam_meta_data_accessKey, S3B_EC2_IAM_META_DATA_ACCESSKEY);
    strcpy(config->http_io_params->ec2_iam_meta_data_token, S3B_EC2_IAM_META_DATA_TOKEN);
    strcpy(config->http_io_params->name_hash_header, S3B_NAME_HASH_HEADER);
    strcpy(config->http_io_params->cb_domain, S3_DOMAIN);

}

/* S3 Destructor */ 
void 
http_io_s3_destroy(struct http_io_private *const priv)
{
    struct http_io_conf *const config = priv->config;
    int r = 0;
    /* Shut down IAM thread */
    if (config->auth.u.s3.ec2iam_role != NULL) {
        (*config->log)(LOG_DEBUG, "waiting for EC2 IAM thread to shutdown");
        if ((r = pthread_cancel(priv->auth_thread)) != 0)
            (*config->log)(LOG_ERR, "pthread_cancel: %s", strerror(r));
        if ((r = pthread_join(priv->auth_thread, NULL)) != 0)
            (*config->log)(LOG_ERR, "pthread_join: %s", strerror(r));
        else
            (*config->log)(LOG_DEBUG, "EC2 IAM thread successfully shutdown");
    }
}

/* AWS verison 2 authentication */
int
http_io_add_auth2(struct http_io_private *priv, struct http_io *const io, time_t now, const void *payload, size_t plen)
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
    snprintf(access_id, sizeof(access_id), "%s", config->auth.u.s3.accessId);
    snprintf(access_key, sizeof(access_key), "%s", config->auth.u.s3.accessKey);
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

/* AWS verison 4 authentication */
int
http_io_add_auth4(struct http_io_private *priv, struct http_io *const io, time_t now, const void *payload, size_t plen)
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
    snprintf(access_id, sizeof(access_id), "%s", config->auth.u.s3.accessId);
    snprintf(access_key, sizeof(access_key), "%s%s", S3B_ACCESS_KEY_PREFIX, config->auth.u.s3.accessKey);
    snprintf(iam_token, sizeof(iam_token), "%s", config->auth.u.s3.iam_token != NULL ? config->auth.u.s3.iam_token : "");
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

    io->headers = http_io_add_header(io->headers, "%s: %s", S3B_CONTENT_SHA256_HEADER, payload_hash_buf);

/****** Add IAM security token header (if any) ******/

    if (*iam_token != '\0')
        io->headers = http_io_add_header(io->headers, "%s: %s", S3B_SECURITY_TOKEN_HEADER, iam_token);

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
    HMAC_Update(&hmac_ctx, (const u_char *)S3B_SERVICE_NAME, strlen(S3B_SERVICE_NAME));
    HMAC_Final(&hmac_ctx, hmac, &hmac_len);
#if DEBUG_AUTHENTICATION
    http_io_prhex(hmac_buf, hmac, hmac_len);
    (*config->log)(LOG_DEBUG, "auth: HMAC[%s] = %sn", S3B_SERVICE_NAME, hmac_buf);
#endif
    HMAC_Init_ex(&hmac_ctx, hmac, hmac_len, EVP_sha256(), NULL);
    HMAC_Update(&hmac_ctx, (const u_char *)S3B_SIGNATURE_TERMINATOR, strlen(S3B_SIGNATURE_TERMINATOR));
    HMAC_Final(&hmac_ctx, hmac, &hmac_len);
#if DEBUG_AUTHENTICATION
    http_io_prhex(hmac_buf, hmac, hmac_len);
    (*config->log)(LOG_DEBUG, "auth: HMAC[%s] = %s", S3B_SIGNATURE_TERMINATOR, hmac_buf);
#endif
/****** Sign the String To Sign ******/

#if DEBUG_AUTHENTICATION
    *sigbuf = '\0';
#endif
    HMAC_Init_ex(&hmac_ctx, hmac, hmac_len, EVP_sha256(), NULL);
    HMAC_Update(&hmac_ctx, (const u_char *)S3B_SIGNATURE_ALGORITHM, strlen(S3B_SIGNATURE_ALGORITHM));
    HMAC_Update(&hmac_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%s\n", S3B_SIGNATURE_ALGORITHM);
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
    HMAC_Update(&hmac_ctx, (const u_char *)S3B_SERVICE_NAME, strlen(S3B_SERVICE_NAME));
    HMAC_Update(&hmac_ctx, (const u_char *)"/", 1);
    HMAC_Update(&hmac_ctx, (const u_char *)S3B_SIGNATURE_TERMINATOR, strlen(S3B_SIGNATURE_TERMINATOR));
    HMAC_Update(&hmac_ctx, (const u_char *)"\n", 1);
#if DEBUG_AUTHENTICATION
    snprintf(sigbuf + strlen(sigbuf), sizeof(sigbuf) - strlen(sigbuf), "%.8s/%s/%s/%s\n",
      datebuf, config->region, S3B_SERVICE_NAME, S3B_SIGNATURE_TERMINATOR);
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
      AUTH_HEADER, S3B_SIGNATURE_ALGORITHM, access_id, datebuf, config->region, S3B_SERVICE_NAME, S3B_SIGNATURE_TERMINATOR,
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

/* update EC2 IAM role authentication thread */
int
update_iam_credentials(struct http_io_private *const priv)
{
    struct http_io_conf *const config = priv->config;
    char urlbuf[sizeof(S3B_EC2_IAM_META_DATA_URLBASE) + 128];
    struct http_io io;
    char buf[2048] = { '\0' };
    char *access_id = NULL;
    char *access_key = NULL;
    char *iam_token = NULL;
    size_t buflen;
    int r = 0;
    
    /* Nothing to do it iam role is null */
    if(config->auth.u.s3.ec2iam_role == NULL)
        return 0;
    
    /* Build URL */
    snprintf(urlbuf, sizeof(urlbuf), "%s%s", S3B_EC2_IAM_META_DATA_URLBASE, config->auth.u.s3.ec2iam_role);

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = s3b_header_parser;
    io.url = urlbuf;
    io.method = HTTP_GET;
    io.dest = buf;
    io.buf_size = sizeof(buf);

    printf("\n io.url = %s", io.url);
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
    if ((access_id = parse_json_field(priv, buf, S3B_EC2_IAM_META_DATA_ACCESSID)) == NULL
      || (access_key = parse_json_field(priv, buf, S3B_EC2_IAM_META_DATA_ACCESSKEY)) == NULL
      || (iam_token = parse_json_field(priv, buf, S3B_EC2_IAM_META_DATA_TOKEN)) == NULL) {
        (*config->log)(LOG_ERR, "failed to extract EC2 IAM credentials from response: %s", strerror(errno));

        free(access_id);
        free(access_key);
        return EINVAL;
    }

    /* Update credentials */
    pthread_mutex_lock(&priv->mutex);

    free(config->auth.u.s3.accessId);
    free(config->auth.u.s3.accessKey);
    free(config->auth.u.s3.iam_token);

    config->auth.u.s3.accessId = access_id;
    config->auth.u.s3.accessKey = access_key;
    config->auth.u.s3.iam_token = iam_token;
    pthread_mutex_unlock(&priv->mutex);

    (*config->log)(LOG_INFO, "successfully updated EC2 IAM credentials from %s", io.url);

    /* Done */
    return 0;
}

int http_io_s3b_bucket_attributes(struct cloudbacker_store *cb, void *arg)
{
    /* Nothing to do */
    return 0;
}

