/*
 * Dynomite - A thin, distributed replication layer for multi non-distributed storages.
 * Copyright (C) 2015 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *_stats_pool_set_ts
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> // for open
#include <unistd.h> //for close
#include <math.h> // to do ceil for number of chunks

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>

#include "dyn_core.h"


/* A 128 bit key  */
static unsigned char *theKey = (unsigned char *)"0123456789012345";

/* A 128 bit IV  */
static unsigned char *theIv = (unsigned char*)"0123456789012345";


/*
 * Function:  entropy_crypto_init
 * --------------------
 *
 * Initialize crypto libraries per connection
 */
void
entropy_crypto_init()
{
	    ERR_load_crypto_strings();
	    OpenSSL_add_all_algorithms();
	    OPENSSL_config(NULL);
}

/*
 * Function:  entropy_crypto_deinit()
 * --------------------
 *
 * Clean crypto libraries per connection
 */
void
entropy_crypto_deinit()
{
	EVP_cleanup();
	ERR_free_strings();
}



/*
 * Function: entropy_decrypt
 * --------------------
 *  Decrypt the input data using the key and the Initialization Vector (IV).
 *  Uses AES_256_CBC
 *
 *  returns: the length of the ciphertext if it has ended successfully,
 *  or the DN_ERROR status.
 *
 */

int entropy_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len = 0;

  /* Create and initialize the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
	  return DN_ERROR;

  /* Initialize the decryption operation with 256 bit AES */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, theKey, theIv))
	  return DN_ERROR;

  /* Provide the message to be decrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	  return DN_ERROR;
  plaintext_len = len;

  /* Finalize the decryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, ciphertext + len, &len))
	  return DN_ERROR;
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


/*
 * Function: entropy_encrypt
 * --------------------
 *  Encrypts the input data using the key and the Initialization Vector (IV).
 *  Uses AES_256_CBC
 *
 *  returns: the length of the ciphertext if it has ended successfully,
 *  or the DN_ERROR status.
 *
 */

int entropy_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len = 0;

  /* Create and initialize the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
	  return DN_ERROR;

  /* Padding */
  if(1 != EVP_CIPHER_CTX_set_padding(ctx,1))
	  return DN_ERROR;

  /* Initialize the encryption operation with 256 bit AES */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, theKey, theIv))
	  return DN_ERROR;

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	  return DN_ERROR;
  ciphertext_len = len;

  /* Finalize the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
	  return DN_ERROR;
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

 // loga("Block size: %d", EVP_CIPHER_block_size(ctx) );

  return ciphertext_len;
}


/*
 * Function: entropy_conn_stop
 * --------------------
 * closes the socket connection
 */

void
entropy_conn_stop(struct entropy *cn)
{
    close(cn->sd);
}

/*
 * Function:  entropy_conn_destroy
 * --------------------
 * Frees up the memory pointer for the connection
 */

void
entropy_conn_destroy(struct entropy *cn)
{
	entropy_conn_stop(cn);
    dn_free(cn);
}

/*
 * Function:  entropy_listen
 * --------------------
 *  returns: r_status for the status of the new socket and
 *  corresponding phases, e.g. socket, bind, listen etc.
 */

rstatus_t
entropy_listen(struct entropy *cn)
{
    rstatus_t status;
    struct sockinfo si;

    status = dn_resolve(&cn->addr, cn->port, &si);
    if (status < 0) {
        return status;
    }

    cn->sd = socket(si.family, SOCK_STREAM, 0);
    if (cn->sd < 0) {
        log_error("reconciliation socket failed: %s", strerror(errno));
        return DN_ERROR;
    }

    status = dn_set_reuseaddr(cn->sd);
    if (status < 0) {
        log_error("reconciliation set reuseaddr on m %d failed: %s", cn->sd, strerror(errno));
        return DN_ERROR;
    }

    status = bind(cn->sd, (struct sockaddr *)&si.addr, si.addrlen);
    if (status < 0) {
        log_error(" reconciliation bind on m %d to addr '%.*s:%u' failed: %s", cn->sd,
                  cn->addr.len, cn->addr.data, cn->port, strerror(errno));
        return DN_ERROR;
    }

    status = listen(cn->sd, SOMAXCONN);
    if (status < 0) {
        log_error("reconciliation listen on m %d failed: %s", cn->sd, strerror(errno));
        return DN_ERROR;
    }


    log_debug(LOG_NOTICE, "reconciliation m %d listening on '%.*s:%u'", cn->sd,
    		cn->addr.len, cn->addr.data, cn->port);

    return DN_OK;
}

/*
 * Function:  entropy_iv_load
 * --------------------
 *
 * Loads the send IV from a file
 */
rstatus_t
entropy_key_iv_load(struct context *ctx){

	int 			fd;
    struct stat     file_stat;
    unsigned char   buff[BUFFER_SIZE];

    struct server_pool *pool = (struct server_pool *) array_get(&ctx->pool, 0);

    /* 1. Check if the String array of the file names has been allocated */
    if (string_empty(&pool->recon_key_file) || string_empty(&pool->recon_iv_file)) {
    	log_error("Could NOT read key or iv file");
    	return DN_ERROR;
    }

    /* 2. allocate char based on the length in the string arrays */
    char key_file_name[pool->recon_key_file.len + 1];
    char iv_file_name[pool->recon_iv_file.len + 1];

    /* copy the content to the allocated array */
    memcpy(key_file_name, pool->recon_key_file.data, pool->recon_key_file.len);
    key_file_name[pool->recon_key_file.len] = '\0';
    memcpy(iv_file_name, pool->recon_iv_file.data, pool->recon_iv_file.len);
    iv_file_name[pool->recon_iv_file.len] = '\0';

    loga("Key File name: %s - IV File name: %s", key_file_name, iv_file_name);

    /* 3. checking if the key and iv files exist using access */
    if( access(key_file_name, F_OK ) < 0 ) {
    	log_error("Error: file %s does not exist", key_file_name);
        return DN_ERROR;
    }
    else if( access(iv_file_name, F_OK ) < 0 ) {
    	log_error("Error: file %s does not exist", iv_file_name);
        return DN_ERROR;
    }

    /* 4. loading the .pem files */
    FILE *key_file = fopen(key_file_name,"r");
    if(key_file == NULL){
    	    log_error("opening key.pem file failed %s", pool->recon_key_file);
    	    return DN_ERROR;
    }
    FILE *iv_file = fopen(iv_file_name,"r");
	if(iv_file == NULL){
	    log_error("opening iv.pem file failed %s", pool->recon_iv_file);
	    return DN_ERROR;
	}

	/* 5. using the file descriptor to do some checking with the BUFFER_SIZE */
    fd = fileno(key_file);
    if (fstat(fd, &file_stat) < 0)   					 /* Get the file size */
    {
        log_error("Error fstat --> %s", strerror(errno));
    	return DN_ERROR;
    }
    else if (file_stat.st_size > BUFFER_SIZE){			/* Compare file size with BUFFER_SIZE */
       	log_error("key file size is bigger then the buffer size");
   	    return DN_ERROR;
    }

    fd = fileno(iv_file);
    if (fstat(fd, &file_stat) < 0)
    {
    	log_error("Error fstat --> %s", strerror(errno));
 	    return DN_ERROR;
    }
    else if (file_stat.st_size > BUFFER_SIZE){
    	log_error("IV file size is bigger then the buffer size");
	    return DN_ERROR;
    }

    /* 6. reading the files for the key and iv */
    if (fgets(buff,BUFFER_SIZE-1,key_file) == NULL){
       	log_error("Processing Key file error");
       	return DN_ERROR;
    }
  //  theKey = (unsigned char *)buff;
    loga("key loaded: %s", theKey);

    memset( buff, '\0', BUFFER_SIZE );
    if (fgets(buff,BUFFER_SIZE-1,iv_file) == NULL){
    	log_error("Processing IV file error");
    	return DN_ERROR;
    }
   // theIv = (unsigned char *)buff;
    loga("iv loaded: %s", theIv);

    return DN_OK;
}

