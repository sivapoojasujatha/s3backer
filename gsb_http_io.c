
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
#include "gsb_http_io.h"

#include <openssl/pem.h>
#include <openssl/pkcs12.h>


/* Authentication functions */
static char *create_jwt_token(const char *gcs_clientId);
static char *create_jwt_authrequest(struct http_io_private *priv );
static int sign_with_p12_key(const struct http_io_conf *const config, char *key_file,
			     const char *pwd, char *plain_text, char *signed_buf, size_t buf_len);
static void http_io_gcs_auth_prepper(CURL *curl, struct http_io *io);

/* NULL-terminated vector of header parsers */
header_parser_t gsb_header_parser[] = {
  file_size_parser, block_size_parser, name_hash_parser,
  etag_parser, hmac_parser, encoding_parser, NULL
};

/* Inititalize gsb http io parameters to be used in http IO requests */
void set_http_io_gsb_params(struct http_io_conf *config)
{
    strcpy(config->http_io_params->file_size_header, GSB_FILE_SIZE_HEADER);
    strcpy(config->http_io_params->block_size_header, GSB_BLOCK_SIZE_HEADER);
    config->http_io_params->block_size_headerval = config->block_size;
    strcpy(config->http_io_params->compression_level_header, GSB_COMPRESSION_LEVEL_HEADER);
    strcpy(config->http_io_params->encrypted_header, GSB_ENCRYPTED_HEADER);
    strcpy(config->http_io_params->encryption_cipher_header, GSB_ENCRYPTION_HEADER);
    strcpy(config->http_io_params->name_hash_header, GSB_NAME_HASH_HEADER);
    strcpy(config->http_io_params->HMAC_Header, GSB_HMAC_HEADER);
    strcpy(config->http_io_params->acl_header,GSB_ACL_HEADER);
    strcpy(config->http_io_params->acl_headerval,config->auth.u.gs.accessType);
    strcpy(config->http_io_params->content_sha256_header, GSB_CONTENT_SHA256_HEADER);
    strcpy(config->http_io_params->storage_class_header, GSB_STORAGE_CLASS_HEADER);

    if( strcasecmp(config->storageClass, SCLASS_GS_NEARLINE) == 0)
       strcpy(config->http_io_params->storage_class_headerval, SCLASS_GS_NEARLINE);
    else if( strcasecmp(config->storageClass, SCLASS_GS_DRA) == 0)
       strcpy(config->http_io_params->storage_class_headerval, SCLASS_GS_DRA);
    else
       strcpy(config->http_io_params->storage_class_headerval, SCLASS_STANDARD);

    if (strcasecmp(config->auth.u.gs.authVersion, AUTH_VERSION_OAUTH2) == 0){
       strcpy(config->http_io_params->date_header, HTTP_DATE_HEADER);
       strcpy(config->http_io_params->date_buf_fmt,HTTP_DATE_BUF_FMT);
    }
    strcpy(config->http_io_params->name_hash_header, GSB_NAME_HASH_HEADER);
    strcpy(config->http_io_params->cb_domain, GS_DOMAIN);
}

/*
 * GCS Destructor
 */ 
void
http_io_gcs_destroy(struct http_io_private *const priv)
{
    struct http_io_conf *const config = priv->config;
    int r = 0;
    /* Shut down GCS authentication thread */
    if (config->auth.u.gs.clientId != NULL) {
         (*config->log)(LOG_DEBUG, "waiting for GCS authentication thread to shutdown");
         if ((r = pthread_cancel(priv->auth_thread)) != 0)
             (*config->log)(LOG_ERR, "pthread_cancel: %s", strerror(r));
         if ((r = pthread_join(priv->auth_thread, NULL)) != 0)
             (*config->log)(LOG_ERR, "pthread_join: %s", strerror(r));
         else
             (*config->log)(LOG_DEBUG, "GCS Authentication thread successfully shutdown");
    }  
}

/* updates gcs credentials, that is gcs authorization token */
int update_gcs_credentials(struct http_io_private *const priv)
{
    struct http_io_conf *const config = priv->config;
    struct http_io io;
    char buf[2048] = { '\0' };
    char *gs_accesstoken =  NULL;
    char urlbuf[256] = GCS_AUTHENTICATION_URL;
    size_t buflen;
    int r = 0;

    /* client Id is must for accessing google cloud storage resources */
    if(config->auth.u.gs.clientId == NULL)
       return EINVAL;

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = gsb_header_parser;
    io.url = urlbuf;
    io.method = "POST";
    io.dest = buf;
    io.buf_size = sizeof(buf);
    
    /* Perform operation */
    (*config->log)(LOG_INFO, "acquiring GCS access token %s", io.url);

    if ((io.post_data = create_jwt_authrequest(priv)) == NULL) {
        r = ENOMEM;
        (*config->log)(LOG_ERR, "failed to build post request to get access token, error: %s",
		       strerror(r));
        return r;
    }

    if ((r = http_io_perform_io(priv, &io,http_io_gcs_auth_prepper)) != 0) {
        r = EBADR;
        (*config->log)(LOG_ERR, "failed to acquire access token from google cloud storage from %s: %s",
		       io.url, strerror(r));
	return r;
    }
    free(io.post_data);

    /* Determine how many bytes we read */
    buflen = io.buf_size - io.bufs.rdremain;
    if (buflen > sizeof(buf) - 1)
        buflen = sizeof(buf) - 1;
    buf[buflen] = '\0';

    /* Find access token in JSON response */
    if ((gs_accesstoken = parse_json_field(priv, buf, GCS_OAUTH2_ACCESS_TOKEN)) == NULL) {
        (*config->log)(LOG_ERR, "failed to extract GCS access token from response: %s", strerror(errno));
        return EINVAL;
    }

    /* Update credentials */
    pthread_mutex_lock(&priv->mutex);
    if (config->auth.u.gs.auth_token) {
	free(config->auth.u.gs.auth_token);
	config->auth.u.gs.auth_token = gs_accesstoken;
    } else {
	config->auth.u.gs.clientId = config->auth.u.gs.clientId;
	config->auth.u.gs.secret_keyfile = config->auth.u.gs.secret_keyfile;
	config->auth.u.gs.auth_token = gs_accesstoken;
    }
    pthread_mutex_unlock(&priv->mutex);
    (*config->log)(LOG_INFO, "successfully updated GCS authentication credentials %s", io.url);
 
    /* Done */
    return 0;
}

/*
 * Google storage oAuth 2.0 authentication
 */
int http_io_add_oAuth2(struct http_io_private *priv, struct http_io *const io, 
					time_t now, const void *payload, size_t plen)
{
    const struct http_io_conf *const config = priv->config;
    int r = 0;  
    
    io->headers = http_io_add_header(io->headers, "%s: Bearer %s", AUTH_HEADER,config->auth.u.gs.auth_token);
    
    return r;
}

static void
http_io_gcs_auth_prepper(CURL *curl, struct http_io *io)
{
    memset(&io->bufs, 0, sizeof(io->bufs));
    io->bufs.rdremain = io->buf_size;
    io->bufs.rddata = io->dest;

    curl_easy_setopt(curl, CURLOPT_URL, GCS_AUTHENTICATION_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_io_curl_reader);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, io);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)io->buf_size);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, io->post_data);
}

/*
 * Function builds jwt header and jwd claimset buffers, and performs base64 encoding on them,
 * returns {base64 encoded jwt header}.{base64 encoded jwt claimset}
*/
static char *
create_jwt_token(const char *gcs_clientId)
{

    char jwt_headerbuf[JWT_HEADER_BUF_LEN];
    char jwt_claimsetbuf[JWT_CLAIMSET_BUF_LEN];
    char b64jwt_headerbuf[512], b64jwt_claimbuf[512];   
    char *jwt_hdr_claim_buf;
    time_t seconds;
    int len, rlen;

    /* {"alg":"RS256","typ":"JWT"}  */
    memset(jwt_headerbuf, 0, JWT_HEADER_BUF_LEN);
    len = snprintf(jwt_headerbuf, JWT_HEADER_BUF_LEN, "{\"%s\":\"%s\",\"%s\":\"%s\"}",
		   JWT_HEADER_ALG, JWT_HEADER_RS256, JWT_HEADER_TYPE, JWT_HEADER_JWT);
    assert(len < JWT_HEADER_BUF_LEN);

    seconds = time(NULL);
    memset(jwt_claimsetbuf, 0, JWT_CLAIMSET_BUF_LEN);
    len = snprintf(jwt_claimsetbuf, JWT_CLAIMSET_BUF_LEN,
		   "{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":%ld,\"%s\":%ld}",
		   JWT_CLAIMSET_ISS, gcs_clientId,
		   JWT_CLAIMSET_SCOPE,JWT_CLAIMSET_SCOPE_VALUE,
		   JWT_CLAIMSET_AUD, JWT_CLAIMSET_AUD_VALUE,
		   JWT_CLAIMSET_EXP, seconds+JWT_CLAIMSET_EXP_DURATION,
		   JWT_CLAIMSET_IAT, seconds);
    assert(len < JWT_CLAIMSET_BUF_LEN);

    memset(b64jwt_headerbuf, 0, sizeof(b64jwt_headerbuf));
    memset(b64jwt_claimbuf, 0, sizeof(b64jwt_claimbuf));

    http_io_base64_encode_safe(b64jwt_headerbuf,sizeof(b64jwt_headerbuf), jwt_headerbuf,
			       strlen(jwt_headerbuf));
    http_io_base64_encode_safe(b64jwt_claimbuf, sizeof(b64jwt_claimbuf), jwt_claimsetbuf,
			       strlen(jwt_claimsetbuf));

    // combine jwt_headerbuf and jwt_claimsetbuf
    len = strlen(b64jwt_headerbuf) + strlen(b64jwt_claimbuf) + 3;
    if ((jwt_hdr_claim_buf = (char *)malloc(len)) == NULL)
        return NULL;
    rlen = snprintf(jwt_hdr_claim_buf, len, "%s%s%s", b64jwt_headerbuf, ".", b64jwt_claimbuf);
    assert(rlen < len);

    return jwt_hdr_claim_buf;
}

   
static char *
create_jwt_authrequest(struct http_io_private *priv)
{
#define BUFLEN	1024
    const struct http_io_conf *const config = priv->config;
    char signed_jwt[BUFLEN], assertion[BUFLEN];
    char *jwt, *postfields;
    int len;

    /* Anything to do? */
    if (config->auth.u.gs.clientId == NULL)
        return 0;

    if ((jwt = create_jwt_token((const char *)config->auth.u.gs.clientId)) == NULL)
        return NULL;

    CRYPTO_malloc_init();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    memset(signed_jwt, 0, BUFLEN);
    if (sign_with_p12_key(config, config->auth.u.gs.secret_keyfile,
			  JWT_AUTH_DEFAULT_PASSWORD, jwt, signed_jwt, BUFLEN))
    	return NULL;

    EVP_cleanup();

    len = snprintf(assertion, BUFLEN, "%s%s%s", jwt, ".", signed_jwt);
    assert(len < BUFLEN);

    free(jwt);
    
    if ((postfields = (char *)malloc(BUFLEN)) == NULL)
    	return NULL;

    len = snprintf(postfields, BUFLEN,
		   "%s%s","grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=",
		   assertion);
    assert(len < BUFLEN);

    return postfields;
}

/*
 * Sign the UTF-8 representation of the input using SHA256withRSA
 * (also known as RSASSA-PKCS1-V1_5-SIGN with the SHA-256 hash function) with the private key.
 */

static int
sign_with_p12_key(const struct http_io_conf *const config, char *key_file,
		  const char *pwd, char *plain_text, char *signed_buf, size_t buflen)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char sign[256];
    unsigned int sign_len = 0;
    FILE *fp = NULL;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    EVP_MD_CTX *ctx = NULL;
    RSA *prikey = NULL;
    SHA256_CTX sha256;
    const char *c;
    int ret;

    memset(hash, 0, SHA256_DIGEST_LENGTH);
    memset(sign, 0, 256);

    if (!(fp = fopen(key_file, "rb"))){        
        (*config->log)(LOG_ERR, "Error opening cert file %s: %s",
		       key_file, strerror(errno));
	return 1;
    }

    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);

    if (!p12) {
        (*config->log)(LOG_ERR, "Error reading PKCS#12 file: %s",
		       strerror(errno));
	return 1;
    }

    STACK_OF(X509) *ca = NULL;
    ret = PKCS12_parse(p12, pwd, &pkey, &x509, &ca);
    PKCS12_free(p12);

    if (ret == 0) {
        (*config->log)(LOG_ERR, "Error parsing PKCS#12 file: %s",
		       strerror(errno));
	return 1;
    }

    sign_len = EVP_PKEY_size(pkey);
    ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);

    prikey = EVP_PKEY_get1_RSA(pkey);

    SHA256_Init(&sha256);
    c = plain_text;
    SHA256_Update(&sha256, c, strlen(c));
    SHA256_Final(hash, &sha256);
      
    ret = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,  &sign_len, prikey);
    EVP_MD_CTX_destroy(ctx);
    RSA_free(prikey);
    EVP_PKEY_free(pkey);
    X509_free(x509);

    if (ret == 0) {
        (*config->log)(LOG_ERR, "Signing p12 key with RSA Signature failed ");
	return 1;
    }
   
    memset(signed_buf, 0, buflen);
    http_io_base64_encode_safe(signed_buf, buflen, sign, sign_len);

    return 0;
}

int http_io_gcs_bucket_attributes(struct cloudbacker_store *cb, void *arg)
{
    struct http_io_private *const priv = cb->data;
    struct http_io_conf *const config = priv->config;
    char urlbuf[URL_BUF_SIZE(config) + sizeof(BUCKET_PARAM_STORAGECLASS)];
    const time_t now = time(NULL);
    struct http_io io;
    int r;
    char buf[2048] = { '\0' };
    size_t buflen;

    /* Initialize I/O info */
    memset(&io, 0, sizeof(io));
    io.header_parser = gsb_header_parser;
    io.url = urlbuf;
    io.method = HTTP_GET;
    io.dest = buf;
    io.buf_size = sizeof(buf);

    /* Construct URL for the first block */
    http_io_get_bucket_url(urlbuf, sizeof(urlbuf), config);

    /* prepare url for http request */
    snprintf(urlbuf + strlen(urlbuf), strlen(BUCKET_PARAM_STORAGECLASS)+2,
	     "?%s", BUCKET_PARAM_STORAGECLASS);

    /* Add Date header */
    http_io_add_date(priv, &io, now);
   
    /* Add Authorization header */
    if ((r = http_io_add_auth(priv, &io, now, NULL, 0)) != 0)
        goto done;

    /* Perform operation */
    if ((r = http_io_perform_io(priv, &io, http_io_read_prepper)) != 0)
    {
       goto done;
    }

    /* buf format <?xml version="1.0" encoding="UTF-8"?><StorageClass>NEARLINE</StorageClass> */
    buflen = io.buf_size - io.bufs.rdremain;
    if (buflen > sizeof(buf) - 1)
        buflen = sizeof(buf) - 1;
    buf[buflen] = '\0';

    /* If xml response is nothaving the storageClass specified by user */
    if (strcasestr(buf,config->storageClass) == NULL) {
        (*config->log)(LOG_ERR, "Incompatible storageClass specified. ");
        curl_slist_free_all(io.headers);
        return EINVAL;
    }

done:
    /*  Clean up */
    curl_slist_free_all(io.headers);
    return r;
}

