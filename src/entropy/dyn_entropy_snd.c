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

/*
 * Function:  compact_aof
 * --------------------
 *
 * Performs background Redis rewrite of aof.
 * It tries to rewrite the aof twice before sending to Spark.
 * If the second time fails, the Socket to spark is closed.
 */

static rstatus_t
compact_aof(){
	char 			command[BUFFER_SIZE];
    int 			sys_ret = 0;

	memset(&command[0], 0, sizeof(command));
    sprintf(command, "redis-cli -p 22122 bgrewriteaof");
    sys_ret = system(command);
    if( sys_ret < 0 ){
	    log_error("Error on system call --> %s", strerror(errno));
	    loga("Thread sleeping 2 seconds and retrying");
	    sleep(2);
	    sys_ret = system(command);
	    if( sys_ret < 0 ){
		    log_error("Error on bgrewriteaof for seconds time --> %s", strerror(errno));
			return DN_ERROR;
	    }
    }
    loga("Redis BGREWRITEAOF completed");
    return DN_OK;
}

/*
 * Function:  entropy_snd_callback
 * --------------------
 *
 * Handling connection for each client on a separate thread
 */

static void
entropy_snd_callback(void *arg1, void *arg2)
{
    struct stat     file_stat;
    ssize_t         transmit_len;
    int peer_socket;
    FILE			*fp = NULL;
    int             fd;
    char            buff[BUFFER_SIZE];
    unsigned char ciphertext[CIPHER_SIZE];
    int ciphertext_len = 0;
    size_t 			nread;
    int				nchunk;
    int 			i; //iterator for chunks
    size_t 			last_chunk_size;
    int n = *((int *)arg2);

    struct entropy *st = arg1;


    /* check for issues */
    if (n == 0 || CIPHER_SIZE < BUFFER_SIZE) {
  //  	log_error("cipher or header size are bigger than buffer size");
  //  	log_error("cipher size: %d -  buffer size: %d - header_size: %d", CIPHER_SIZE, BUFFER_SIZE, HEADER_SIZE);
   	    return;
    }

    if(ENCRYPT_FLAG == 0){
    	loga("WARNING: Encryption is disabled for reconciliation");
    }
    else{
    	entropy_crypto_init();
    }


    /* accept the connection */
    peer_socket = accept(st->sd, NULL, NULL);
    if(peer_socket < 0){
    	log_error("peer socket coould not be established");
    	goto error;
    }
    loga("Spark socket connection accepted"); //TODO: print information about the socket IP address.

    /* compact AOF in Redis before sending to Spark */
    if(compact_aof() == DN_ERROR){
    	log_error("Redis failed to perform bgrewriteaof");
    	goto error;
    }

    /* create a file pointer for the AOF */
    fp = fopen(AOF_TO_SEND, "r");
    if (fp == NULL)
    {
    	log_error("Error opening Redis AOF file: %s", strerror(errno));
    	goto error;
    }
    loga("Redis AOF loaded successfully");

    /* Get the file descriptor from the file pointer */
    fd = fileno(fp);

    /* Get the file size to include in the header */
    if (fstat(fd, &file_stat) < 0)
    {
    	 log_error("Error fstat --> %s", strerror(errno));
     	 goto error;
    }

    /* Constructing the header: file size & buffer size */
    memset(&buff[0], 0, sizeof(buff));
    buff[0] = (int)((((int)file_stat.st_size) >> 24) & 0xFF);
    buff[1] = (int)((((int)file_stat.st_size) >> 16) & 0xFF);
    buff[2] = (int)((((int)file_stat.st_size) >> 8) & 0XFF);
    buff[3] = (int)((((int)file_stat.st_size) & 0XFF));

    buff[4] = (int)((BUFFER_SIZE >> 24) & 0xFF);
    buff[5] = (int)((BUFFER_SIZE >> 16) & 0xFF);
    buff[6] = (int)((BUFFER_SIZE >> 8) & 0XFF);
    buff[7] = (int)((BUFFER_SIZE & 0XFF));


    /* Header transmission */
    if(ENCRYPT_FLAG == 1) {
        ciphertext_len = entropy_encrypt (buff, HEADER_SIZE, ciphertext);
        if(ciphertext_len <0)
        {
        	log_error("Error encrypting the AOF file size");
        	goto error;
        }
        loga("Ciphertext Length is %d",ciphertext_len);
    	transmit_len = send(peer_socket, ciphertext, sizeof(ciphertext), 0);
        loga("The size of the cipher text is %d",sizeof(ciphertext));
    }
    else{
    	transmit_len = send(peer_socket, buff, sizeof(buff), 0);
    	loga("The size of header is %d",sizeof(buff));
    }

	if (transmit_len < 0)
	{
	    log_error("Error on sending AOF file size --> %s", strerror(errno));
    	goto error;
    }
	else if (transmit_len > CIPHER_SIZE){
		log_error("Header Transmit Length is longer than CIPHER SIZE --> "
				"transmit: %d cipher size: %d", transmit_len, CIPHER_SIZE);
    	 goto error;
	}


	/* Determine the number of chunks
	 * if the size of the file is larger than the Buffer size
	 * then split it, otherwise we need one chunk only.
	 *  */
	if(file_stat.st_size > BUFFER_SIZE){
		nchunk = (int)(ceil(file_stat.st_size/BUFFER_SIZE) + 1);
	}
	else{
		nchunk = 1;
	}

    /* Last chunk size is calculated by subtracting from the total file size
     * the size of each chunk excluding the last one.
     */
   	last_chunk_size = (long)(file_stat.st_size - (nchunk-1) * BUFFER_SIZE);

	loga("AOF File size %d - Chunk Size %d - Number of chunks %d - last chunk size: %ld",
			file_stat.st_size, BUFFER_SIZE, nchunk, last_chunk_size);

    for(i=0; i<nchunk; i++){

        /* clear buffer before using it */
        memset(&buff[0], 0, sizeof(buff));
        /* Read file data in chunks of BUFFER_SIZE bytes */
        if(i<nchunk-1){
        	nread = fread (buff, sizeof(char), BUFFER_SIZE, fp);
            ciphertext_len = entropy_encrypt (buff, BUFFER_SIZE, ciphertext);
        }
        else{
        	nread = fread (buff, sizeof(char), last_chunk_size, fp);
            ciphertext_len = entropy_encrypt (buff, last_chunk_size, ciphertext);
        }
        /* checking for errors */
    	if (nread < 0){
    		 log_error("Error reading chunk of AOF file --> %s", strerror(errno));
         	 goto error;
    	}

        /* transmit the chunk encrypted/unencrypted */
        if(ENCRYPT_FLAG == 1){
        	if(ciphertext_len <0){
        		log_error("Error encrypting the AOF chunk --> %s", strerror(errno));
            	 goto error;
        	}
        	transmit_len = send(peer_socket, ciphertext, sizeof(ciphertext), 0);
        }
        else{
        	if(i<nchunk-1){
        		transmit_len = send(peer_socket, buff, BUFFER_SIZE, 0);
        	}
        	else{
        		transmit_len = send(peer_socket, buff, last_chunk_size, 0);
        	}
        }

    	if (transmit_len < 0){
    		 log_error("Error sending the AOF chunk --> %s", strerror(errno));
         	 goto error;
    	}

    }

	/* clean up */
	if(ENCRYPT_FLAG == 1)
		entropy_crypto_deinit();

	fclose(fp);
	close(peer_socket);
    loga("Chunks transferred: %d ---> AOF transfer completed!", i);

    return;

error:
	/* clean up resources after error */
	if(ENCRYPT_FLAG == 1)
		entropy_crypto_deinit();

	fclose(fp);
	close(peer_socket);
	log_error("Closing socket because of entropy error.");
    return;

}

static void *
entropy_loop(void *arg)
{
    event_loop_entropy(entropy_snd_callback, arg);
    return NULL;
}


/*
 * Function: (static) entropy_conn_start
 * --------------------
 * Checks if resources are available, and initializes the connection information.
 * Loads the IV and creates a new thread to loop for the entropy receive.
 *
 *  returns: r_status for the status of opening of the new connection.
 */

static rstatus_t
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



/*
 * Function:  entropy_snd_init
 * --------------------
 * Initiates the data for the connection towards another cluster for reconciliation
 *
 *  returns: a entropy_conn structure with information about the connection
 *           or NULL if a new thread cannot be picked up.
 */

struct entropy *entropy_snd_init(uint16_t entropy_port, char *entropy_ip, struct context *ctx)
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
    keyIVLoaded = 1;

    cn->port = entropy_port;
    string_set_raw(&cn->addr, entropy_ip);

    cn->entropy_ts = (int64_t)time(NULL);
    cn->tid = (pthread_t) -1; //Initialize thread id to -1
    cn->sd = -1; // Initialize socket descriptor to -1

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
