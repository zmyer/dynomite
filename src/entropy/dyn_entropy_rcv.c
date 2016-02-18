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

#define DECRYPT_FLAG			0


/*
 * Function:  entropy_redis_connector
 * --------------------
 *
 *  returns: rstatus_t for the status of opening of the redis connection.
 */

static int
entropy_redis_connector(){
    loga("trying to connect to Redis...");

    struct sockaddr_in serv_addr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
    	log_error("open socket to Redis failed");
    	return -1;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* set destination IP number - localhost, 127.0.0.1*/
    serv_addr.sin_port = htons(22122);
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0){
    	log_error("connecting to Redis failed");
    	return -1;
    }

    loga("redis-server connection established: %d", sockfd);
    return sockfd;

}

/*
 * Function:  entropy_rcv_callback
 * --------------------
 *
 * Handling connection for each client on a separate thread
 */

static void
entropy_rcv_callback(void *arg1, void *arg2)
{
    int 			peer_socket;
    int 			redis_socket = 0;
    char 			aof[BUFFER_SIZE];
    char            buff[BUFFER_SIZE];
    unsigned char ciphertext[CIPHER_SIZE];
    int32_t 		keyValueLength;
    int32_t			tempInt;
    int 			i = 0;
    int 			numberOfKeys;
	int redis_written_bytes = 0;


    int n = *((int *)arg2);
    struct entropy *st = arg1;

    if (n == 0) {
   	    return;
    }

    /* Check the encryption flag and initialize the crypto */
    if(DECRYPT_FLAG == 1){
    	entropy_crypto_init();
    }
    else{
    	loga("Encryption is disabled for entropy receiver");
    }

    /* Open the peer socket */
    peer_socket = accept(st->sd, NULL, NULL);
    if(peer_socket < 0){
    	log_error("peer socket could not be established");
    	goto error;
    }
    loga("Spark downloader socket connection accepted"); //TODO: print information about the socket IP address.

    /* Processing header for number of Keys */
    if(DECRYPT_FLAG == 1) {
    	int bytesRead = read(peer_socket, ciphertext, CIPHER_SIZE);
    	if( bytesRead < 1 ){
    	    log_error("Error on receiving number of keys --> %s", strerror(errno));
    	    goto error;
    	}
    	loga("Bytes read %d", bytesRead);
    	if( entropy_decrypt (ciphertext, BUFFER_SIZE, buff) < 0 )
    	{
        	log_error("Error decrypting the AOF file size");
         	goto error;
    	}
    	numberOfKeys = ntohl(buff);

    }
    else{
        if( read(peer_socket, &tempInt, sizeof(int32_t)) < 1 ){
        	log_error("Error on receiving number of keys --> %s", strerror(errno));
        	goto error;
        }
        numberOfKeys = ntohl(tempInt);
    }
    if (numberOfKeys < 0) {
    	log_error("receive header not processed properly");
    	goto error;
    }
    else if (numberOfKeys == 0) {
    	log_error("no keys sent");
    	goto error;
    }
    loga("Expected number of keys: %d", numberOfKeys);

    /* Connect to redis-server */
    redis_socket = entropy_redis_connector();
    if(redis_socket == -1){
    	goto error;
    }

    /* Iterating around the keys */
    for(i=0; i<numberOfKeys; i++){

    	/*
    	 * if the encrypt flag is set then, we need to decrypt the aof size
    	 * and then decrypt the key/OldValue/newValue in Redis serialized format.
    	 */
        if(DECRYPT_FLAG == 1) {
        	if( read(peer_socket, ciphertext, CIPHER_SIZE) < 1 ){
        	   log_error("Error on receiving aof size --> %s", strerror(errno));
        	   goto error;
        	}
           	if( entropy_decrypt (ciphertext, BUFFER_SIZE, buff) < 0 )
            {
                log_error("Error decrypting the buffer for AOF file size");
                goto error;
            }
           	keyValueLength = ntohl(buff);
        	log_info("AOF Length: %d", keyValueLength);
            memset(&aof[0], 0, sizeof(aof));
            if( read(peer_socket, ciphertext, CIPHER_SIZE) < 1 ){
                log_error("Error on receiving aof size --> %s", strerror(errno));
                goto error;
            }
            if( entropy_decrypt (ciphertext, BUFFER_SIZE, aof) < 0 )		//TODO: I am not sure the BUFFER_SIZE is correct here.
            {
                log_error("Error decrypting the buffer for key/oldValue/newValue");
                goto error;
             }
        }
        else{
        	/* Step 1: Read the key/Value size */
           	if( read(peer_socket, &keyValueLength, sizeof(int32_t)) < 1 ){
            	log_error("Error on receiving aof size --> %s", strerror(errno));
            	goto error;
            }
           	keyValueLength = ntohl(keyValueLength);
        	log_info("AOF Length: %d", keyValueLength);
            memset(&aof[0], 0, sizeof(aof));

            /* Step 2: Read the key/Value using the keyValueLength */
           	if( read(peer_socket, &aof, keyValueLength) < 1 ){
            	log_error("Error on receiving aof file --> %s", strerror(errno));
            	goto error;
            }
        }
       	loga("Key: %d/%d - Redis serialized form: \n%s", i+1,numberOfKeys,aof);
       	redis_written_bytes = write(redis_socket, &aof, keyValueLength);
       	if( redis_written_bytes < 1 ){
        	log_error("Error on writing to Redis, bytes: %d --> %s", redis_written_bytes, strerror(errno));
        	goto error;
        }
       	loga("Bytes written to Redis %d", redis_written_bytes);
    }

	/* Clean up */
    if(DECRYPT_FLAG == 1)
    	entropy_crypto_deinit();

	close(peer_socket);
	close(redis_socket);
	loga("entropy rcv closing socket gracefully.");
  	return;

error:
	/* Clean resources after error */
	if(DECRYPT_FLAG == 1)
		entropy_crypto_deinit();

	close(peer_socket);
  	if(redis_socket > -1)
  		close(redis_socket);

  	log_error("entropy rcv closing socket because of error.");
  	return;


}


static void *
entropy_loop(void *arg)
{
    event_loop_entropy(entropy_rcv_callback, arg);
	return NULL;
}


/*
 * Function: (static) entropy_conn_start
 * --------------------
 * Checks if resources are available, and initializes the connection information.
 * Loads the IV and creates a new thread to loop for the entropy receive.
 *
 *  returns: rstatus_t for the status of opening of the new connection.
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
 * Function:  entropy_rcv_init
 * --------------------
 * Initiates the data for the connection towards another cluster for reconciliation
 *
 *  returns: a entropy_conn structure with information about the connection
 *           or NULL if a new thread cannot be picked up.
 */

struct entropy *entropy_rcv_init(uint16_t entropy_port, char *entropy_ip, struct context *ctx)
{

    rstatus_t status;
    struct entropy *cn;

    cn = dn_alloc(sizeof(*cn));
    if (cn == NULL) {
       log_error("Cannot allocate rcv entropy structure");
       goto error;
    }
    else if(keyIVLoaded == 0){
       log_error("Key or IV have not been loaded during the entropy sender initialization");
       goto error;
    }

    cn->port = entropy_port;
    string_set_raw(&cn->addr, entropy_ip);

    cn->entropy_ts = (int64_t)time(NULL);
    cn->tid = (pthread_t) -1; 	//Initialize thread id to -1
    cn->sd = -1; 				// Initialize socket descriptor to -1
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
