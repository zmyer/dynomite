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

#define ENCRYPT_FLAG			0
#define AOF_TO_SEND		"/mnt/data/nfredis/appendonly.aof"	/* later on add as command line property */


/*
 * Function:  entropy_redis_compact_aof
 * --------------------
 *
 * Performs background Redis rewrite of aof.
 * It tries to rewrite the aof twice before sending to Spark.
 * If the second time fails, the Socket to spark is closed.
 */

static rstatus_t
entropy_redis_compact_aof(){
	char 			command[BUFFER_SIZE];
    int 			sys_ret = 0;

	memset(&command[0], 0, sizeof(command));
    sprintf(command, "redis-cli -p 22122 bgrewriteaof");
    sys_ret = system(command);
    if( sys_ret < 0 ){
	    log_error("Error on system call --> %s", strerror(errno));
	    loga("Thread sleeping 10 seconds and retrying");
	    sleep(10);
	    sys_ret = system(command);
	    if( sys_ret < 0 ){
		    log_error("Error on bgrewriteaof for seconds time --> %s", strerror(errno));
			return DN_ERROR;
	    }
    }
    else if( sys_ret > 0 ){
    	log_error("Cannot connect to Redis on port 22122: %d", sys_ret);
    	return DN_ERROR;
    }
    loga("Redis BGREWRITEAOF completed");
    return DN_OK;
}

/*
 * Function:  header_send
 * --------------------
 *
 * Sending summary information in a header;
 * Header Format: file size | buffer size | cipher size | encryption | data store
 *
 */
static rstatus_t
header_send(struct stat file_stat, int peer_socket)
{
    char			header_buff[HEADER_SIZE];
    ssize_t         transmit_len;

    memset(&header_buff[0], 0, sizeof(header_buff));
    header_buff[0] = (int)((((int)file_stat.st_size) >> 24) & 0xFF);
    header_buff[1] = (int)((((int)file_stat.st_size) >> 16) & 0xFF);
    header_buff[2] = (int)((((int)file_stat.st_size) >> 8) & 0XFF);
    header_buff[3] = (int)((((int)file_stat.st_size) & 0XFF));

    header_buff[4] = (int)((BUFFER_SIZE >> 24) & 0xFF);
    header_buff[5] = (int)((BUFFER_SIZE >> 16) & 0xFF);
    header_buff[6] = (int)((BUFFER_SIZE >> 8) & 0XFF);
    header_buff[7] = (int)((BUFFER_SIZE & 0XFF));

    header_buff[8] = (int)((CIPHER_SIZE >> 24) & 0xFF);
    header_buff[9] = (int)((CIPHER_SIZE >> 16) & 0xFF);
    header_buff[10] = (int)((CIPHER_SIZE >> 8) & 0XFF);
    header_buff[11] = (int)((CIPHER_SIZE & 0XFF));

    // TODO: encrypt flag does not have to be int but a single byte.
    header_buff[12] = (int)((ENCRYPT_FLAG >> 24) & 0xFF);
    header_buff[13] = (int)((ENCRYPT_FLAG >> 16) & 0xFF);
    header_buff[14] = (int)((ENCRYPT_FLAG >> 8) & 0XFF);
    header_buff[15] = (int)((ENCRYPT_FLAG & 0XFF));

    //TODO: we can add data store information as well

  	transmit_len = send(peer_socket, header_buff, sizeof(header_buff), 0);
  	if (transmit_len < 0)
  	{
  	    log_error("Error on sending AOF file size --> %s", strerror(errno));
      	return DN_ERROR;
    }
  	else if (transmit_len > CIPHER_SIZE){
  		log_error("Header Transmit Length is longer than CIPHER SIZE --> "
  				"transmit: %d cipher size: %d", transmit_len, CIPHER_SIZE);
      	return DN_ERROR;
  	}
  	loga("The size of header is %d",sizeof(header_buff)); //TODO: this can be moved to log_info
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
    ssize_t			data_trasmitted = 0;
    int peer_socket;
    FILE			*fp = NULL;
    int             fd;
    char            data_buff[BUFFER_SIZE];
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
    	log_error("peer socket could not be established");
    	goto error;
    }
    loga("Spark socket connection accepted"); //TODO: print information about the socket IP address.

    /* compact AOF in Redis before sending to Spark */
    if(entropy_redis_compact_aof() == DN_ERROR){
    	log_error("Redis failed to perform bgrewriteaof");
    	goto error;
    }
    /* short sleep to finish AOF rewriting */
    sleep(1);

    /* create a file pointer for the AOF */
    fp = fopen(AOF_TO_SEND, "r");
    if (fp == NULL)
    {
    	log_error("Error opening Redis AOF file: %s", strerror(errno));
    	goto error;
    }

    /* Get the file descriptor from the file pointer */
    fd = fileno(fp);

    /* Get the file size */
    if (fstat(fd, &file_stat) < 0)
    {
    	 log_error("Error fstat --> %s", strerror(errno));
     	 goto error;
    }

    /* No file AOF found to send */
    if(file_stat.st_size == 0){
    	log_error("Cannot retrieve an AOF file in %s", AOF_TO_SEND);
    	goto error;
    }
    loga("Redis appendonly.aof ready to be sent");


    /* sending header */
    if(header_send(file_stat, peer_socket)==DN_ERROR){
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

	loga("HEADER INFO: file size: %d -- buffer size: %d -- cipher size: %d -- encryption: %d ",
			(int)file_stat.st_size, BUFFER_SIZE, CIPHER_SIZE, ENCRYPT_FLAG);
	loga("CHUNK INFO: number of chunks: %d -- last chunk size: %ld", nchunk, last_chunk_size);

    for(i=0; i<nchunk; i++){

        /* clear buffer before using it */
        memset(data_buff, 0, sizeof(data_buff));

        /* Read file data in chunks of BUFFER_SIZE bytes */
        if(i < nchunk-1){
        	nread = fread (data_buff, sizeof(char), BUFFER_SIZE, fp);
        }
        else{
        	nread = fread (data_buff, sizeof(char), last_chunk_size, fp);
        }

        /* checking for errors */
    	if (nread < 0){
    		 log_error("Error reading chunk of AOF file --> %s", strerror(errno));
         	 goto error;
    	}
        /* transmit the chunk encrypted/unencrypted */
        if(ENCRYPT_FLAG == 1){
        	if (i < nchunk-1){
                ciphertext_len = entropy_encrypt (data_buff, BUFFER_SIZE, ciphertext);
        	}
        	else{
                ciphertext_len = entropy_encrypt (data_buff, last_chunk_size, ciphertext);
                loga("Size of last chunk: %d", sizeof(data_buff));
        	}
        	if(ciphertext_len < 0){
        		log_error("Error encrypting the AOF chunk --> %s", strerror(errno));
            	 goto error;
        	}
        	transmit_len = send(peer_socket, ciphertext, sizeof(ciphertext), 0);
        }
        else{
        	if(i<nchunk-1){
        		transmit_len = send(peer_socket, data_buff, BUFFER_SIZE, 0);
        	}
        	else{
        		transmit_len = send(peer_socket, data_buff, last_chunk_size, 0);
        	}
        }

    	if (transmit_len < 0){
    		 log_error("Error sending the AOF chunk --> %s", strerror(errno));
    		 log_error("Data transmitted up to error: %ld and chunks: %d", data_trasmitted, i+1);
         	 goto error;
    	}
    	else if ( transmit_len == 0){
    		 loga("No data in chunk");
    	}
    	else{
    		data_trasmitted +=transmit_len;
    	}
    }

    loga("Chunks transferred: %d ---> AOF transfer completed!", i);

	/* clean up */
	if(ENCRYPT_FLAG == 1)
		entropy_crypto_deinit();

	if(fp!=NULL)
		fclose(fp);

	close(peer_socket);
    loga("Sender entropy resource cleaning complete");

    return;

error:
	/* clean up resources after error */
	if(ENCRYPT_FLAG == 1)
		entropy_crypto_deinit();

	if(fp!=NULL)
		fclose(fp);

	close(peer_socket);
	log_error("Closing sender entropy socket (check for above for possible errors).");
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
