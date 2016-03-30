/*
 * Dynomite - A thin, distributed replication layer for multi non-distributed storages.
 * Copyright (C) 2016 Netflix, Inc.
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

/* Define max values so that Dynomite operates under limits */
#define MAX_HEADER_SIZE 1024
#define MAX_BUFFER_SIZE 5120000 //5MB
#define MAX_CIPHER_SIZE 5120000	//5MB

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
  if(1 != EVP_CIPHER_CTX_set_padding(ctx,0))
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
        log_error("anti-entropy socket failed: %s", strerror(errno));
        return DN_ERROR;
    }

    status = dn_set_reuseaddr(cn->sd);
    if (status < 0) {
        log_error("anti-entropy set reuseaddr on m %d failed: %s", cn->sd, strerror(errno));
        return DN_ERROR;
    }

    status = bind(cn->sd, (struct sockaddr *)&si.addr, si.addrlen);
    if (status < 0) {
        log_error(" anti-entropy bind on m %d to addr '%.*s:%u' failed: %s", cn->sd,
                  cn->addr.len, cn->addr.data, cn->port, strerror(errno));
        return DN_ERROR;
    }

    status = listen(cn->sd, SOMAXCONN);
    if (status < 0) {
        log_error("anti-entropy listen on m %d failed: %s", cn->sd, strerror(errno));
        return DN_ERROR;
    }


    log_debug(LOG_NOTICE, "anti-entropy m %d listening on '%.*s:%u'", cn->sd,
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


/*
 * Function:  entropy_snd_init
 * --------------------
 * Initiates the data for the connection towards another cluster for reconciliation
 *
 *  returns: a entropy_conn structure with information about the connection
 *           or NULL if a new thread cannot be picked up.
 */

struct entropy *entropy_init(uint16_t entropy_port, char *entropy_ip, struct context *ctx)
{

    rstatus_t status;
    struct entropy *cn;

    cn = dn_alloc(sizeof(*cn));
    if (cn == NULL) {
        log_error("Cannot allocate snd entropy structure");
        goto error;
    }

    /* Loading of key/iv happens only once by calling entropy_key_iv_load which is a util function.
     * The same key/iv are reused in the entropy_rcv_init as well.
     */
    if(entropy_key_iv_load(ctx) == DN_ERROR){										//TODO: we do not need to do that if encryption flag is not set.
    	log_error("recon_key.pem or recon_iv.pem cannot be loaded properly");
        goto error;
    }

    cn->port = entropy_port;
    string_set_raw(&cn->addr, entropy_ip);

    cn->entropy_ts = (int64_t)time(NULL);
    cn->tid = (pthread_t) -1; //Initialize thread id to -1
    cn->sd = -1; // Initialize socket descriptor to -1
    cn->redis_sd = -1;			// Initialize redis socket descriptor to -1

    status = entropy_conn_start(cn);
    if (status != DN_OK) {
       goto error;
    }

    cn->ctx = ctx;
    return cn;

error:
    entropy_conn_destroy(cn);
    return NULL;
}

/*
 * Function:  entropy_callback
 * --------------------
 *
 * Handling connection on a separate thread.
 * The entropy_callback is used to accept the connection,
 * process the header from the entropy header and perform
 * an action (send the snapshot or receive data from the
 * entropy engine).
 */

static void
entropy_callback(void *arg1, void *arg2)
{

    int n = *((int *)arg2);
    struct entropy *st = arg1;

    if (n == 0) {
   	    return;
    }

    /* Check the encryption flag and initialize the crypto */
    if(ENCRYPT_FLAG == 1 || DECRYPT_FLAG == 1) {
    	entropy_crypto_init();
    }
    else if (ENCRYPT_FLAG == 0) {
    	loga("Encryption is disabled for entropy sender");

    }
    else if (DECRYPT_FLAG == 0) {
    	loga("Decryption is disabled for entropy receiver");
    }

    /* accept the connection */
    int peer_socket = accept(st->sd, NULL, NULL);
    if(peer_socket < 0){
    	log_error("peer socket could not be established");
    	goto error;
    }
    loga("Spark socket connection accepted"); //TODO: print information about the socket IP address.

    /* Read header from Lepton */
    int32_t sndOrRcv = 0;
    if( read(peer_socket, &sndOrRcv, sizeof(int32_t)) < 1) {
        log_error("Error on processing header from Lepton --> %s", strerror(errno));
    	goto error;
    }
    sndOrRcv = ntohl(sndOrRcv);

    int32_t headerSize;
    if( read(peer_socket, &headerSize, sizeof(int32_t)) < 1) {
        log_error("Error on processing header size from Lepton --> %s", strerror(errno));
    	goto error;
    }
    headerSize = ntohl(headerSize);

    int32_t bufferSize;
    if( read(peer_socket, &bufferSize, sizeof(int32_t)) < 1) {
        log_error("Error on processing buffer size from Lepton --> %s", strerror(errno));
    	goto error;
    }
    bufferSize = ntohl(bufferSize);

    int32_t cipherSize;
    if( read(peer_socket, &cipherSize, sizeof(int32_t)) < 1) {
        log_error("Error on processing cipher size from Lepton --> %s", strerror(errno));
       	goto error;
    }
    cipherSize = ntohl(cipherSize);


    if (sndOrRcv != 1 && sndOrRcv !=2) {
    	log_error("Error on receiving PULL/PUSH --> %s ----> %d", strerror(errno),sndOrRcv);
    	goto error;
    }

    if (headerSize < 1 || headerSize > MAX_HEADER_SIZE){
    	log_error("Header size was not received --> %d", headerSize);
    	goto error;
    }

    if (bufferSize < 1 || bufferSize > MAX_BUFFER_SIZE){
    	log_error("Buffer size was not received --> %d", bufferSize);
    	goto error;
    }

    if (cipherSize < 1 || cipherSize > MAX_CIPHER_SIZE){
    	log_error("Cipher size was not received --> %d", cipherSize);
    	goto error;
    }


    loga("Header size: %d Buffer size: %d Cipher size: %d", headerSize, bufferSize, cipherSize);

    if (cipherSize <= bufferSize){
    	log_error("AES encryption does not allow cipher size to be smaller than buffer size "
    			"-- Cipher size: %d buffer size %d", cipherSize, bufferSize);
    	goto error;
    }
    if (sndOrRcv == 1) {
    	loga("PULL: Dynomite to send data to entropy engine");
    	if (entropy_snd_start(peer_socket, headerSize, bufferSize, cipherSize) == DN_ERROR){
    		log_error("Entropy send faced issue ---> cleaning resources");
    		goto error;
    	}
    	else{
    		loga("Entropy receive completed ---> cleaning resources");
    	}

    }
    else if (sndOrRcv == 2) {
    	loga("PUSH: Dynomite to receive data from entropy engine");
    	if (entropy_rcv_start(peer_socket, headerSize, bufferSize, cipherSize) == DN_ERROR){
    		log_error("Entropy receive faced issue ---> cleaning resources");
    		goto error;
    	}
    	else{
    		loga("Entropy send completed ---> cleaning resources");
    	}
    }



    if(ENCRYPT_FLAG == 1 || DECRYPT_FLAG == 1)
		entropy_crypto_deinit();

    if(peer_socket > -1)
    	close(peer_socket);

    return;

/* resource cleanup */
error:

	if(ENCRYPT_FLAG == 1 || DECRYPT_FLAG == 1)
		entropy_crypto_deinit();

    if(peer_socket > -1)
    	close(peer_socket);

	return;

}

void *
entropy_loop(void *arg)
{
    event_loop_entropy(entropy_callback, arg);
	return NULL;
}


/*
 * Function: entropy_conn_start
 * --------------------
 * Checks if resources are available, and initializes the connection information.
 * Loads the IV and creates a new thread to loop for the entropy receive.
 *
 *  returns: rstatus_t for the status of opening of the new connection.
 */

rstatus_t
entropy_conn_start(struct entropy *cn)
{
    rstatus_t status;

    THROW_STATUS(entropy_listen(cn));

    status = pthread_create(&cn->tid, NULL, entropy_loop, cn);
    if (status < 0) {
        log_error("reconciliation thread for socket create failed: %s", strerror(status));
        return DN_ERROR;
    }

    return DN_OK;
}
