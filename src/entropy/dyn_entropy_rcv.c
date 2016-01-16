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
 * Function:  redisConnector
 * --------------------
 *
 *  returns: rstatus_t for the status of opening of the redis connection.
 */

static int
redisConnector(){
    /* opening the socket to local Redis */
    struct hostent *server;

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
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)

    loga("redis-server connection established");
    return sockfd;

}

/*
 * Function:  entropy_rcv_crypto_init
 * --------------------
 *
 * Initialize crypto libraries
 */
static void
entropy_rcv_crypto_init()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

/*
 * Function:  entropy_rcv_crypto_deinit
 * --------------------
 *
 * Clean crypto
 */
static void
entropy_rcv_crypto_deinit()
{
	EVP_cleanup();
    ERR_free_strings();
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
    ssize_t         received_len, written_len;
    int 			peer_socket,redis_socket;
    char 			aof[BUFFER_SIZE];
    char            buff[BUFFER_SIZE];
    unsigned char ciphertext[CIPHER_SIZE];
    int32_t 		aofLength;
    int32_t			tempInt;
    int 			ciphertext_len = 0;
    int 			sys_ret = 0;
    int 			i = 0;
    int 			numberOfKeys;


    int n = *((int *)arg2);
    struct entropy *st = arg1;

    if (n == 0) {
   	    return;
    }

    /* Check the encryption flag */
    if(ENCRYPT_FLAG == 0){
    	loga("WARNING: Encryption is disabled for reconciliation");
    }
    else{
    	entropy_crypto_init();
    }

    /* Open the peer socket */
    peer_socket = accept(st->sd, NULL, NULL);
    if(peer_socket < 0){
    	log_error("peer socket could not be established");
    	goto error;
    }
    loga("Spark downloader socket connection accepted"); //TODO: print information about the socket IP address.


    /* Processing header for number of Keys */
    if(ENCRYPT_FLAG == 1) {
       ciphertext_len = entropy_decrypt (ciphertext, HEADER_SIZE, buff);
       if(ciphertext_len <0)
       {
        	log_error("Error encrypting the AOF file size");
         	goto error;
       }
    }
    else{
    	received_len = read(peer_socket, &tempInt, sizeof(int32_t));
        numberOfKeys = ntohl(tempInt);
        if( received_len < 1 ){
        	log_error("Error on receiving number of keys --> %s", strerror(errno));
        	goto error;
        }
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
    redis_socket = redisConnector();
    if(redis_socket == -1){
    	goto error;
    }

    /* Iterating around the keys */
    for(i=0; i<numberOfKeys; i++){
    	received_len = read(peer_socket, &aofLength, sizeof(int32_t));
    	aofLength = ntohl(aofLength);
       	if( received_len < 1 ){
        	log_error("Error on receiving aof size --> %s", strerror(errno));
        	goto error;
        }

        memset(&aof[0], 0, sizeof(aof));
    	received_len = read(peer_socket, &aof, aofLength);
       	if( received_len < 1 ){
        	log_error("Error on receiving aof file --> %s", strerror(errno));
        	goto error;
        }
       	loga("AOF: \n%s", aof);

       	//TODO: add the decryption here;

       	written_len = write(redis_socket, &aof, aofLength);
       	if( written_len < 1 ){
        	log_error("Error on writing to Redis --> %s", strerror(errno));
        	goto error;
        }
    }

	/* Clean up */
    if(ENCRYPT_FLAG == 1)
    	entropy_crypto_deinit();

	close(peer_socket);
	close(redis_socket);
	loga("entropy rcv closing socket gracefully.");
  	return;

error:
	/* Clean resources after error */
	if(ENCRYPT_FLAG == 1)
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
