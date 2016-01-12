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
 * Function:  entropy_rcv_callback
 * --------------------
 *
 * Handling connection for each client on a separate thread
 */

static void
entropy_rcv_callback(void *arg1, void *arg2)
{
    ssize_t         received_len;
    int 			peer_socket;
    char 			command[BUFFER_SIZE];				//TODO: create dynamic strings.
    char			redisKey[BUFFER_SIZE];
    char			newValue[BUFFER_SIZE];
    char			oldValue[BUFFER_SIZE];

    int32_t 		keyLength;
    int32_t 		newValueLength;
    int32_t 		oldValueLength;
    int32_t			tempInt;
    int 			sys_ret = 0;
    int 			i = 0;
    int 			numberOfKeys;


    int n = *((int *)arg2);
    struct entropy *st = arg1;

    if (n == 0) {
   	    return;
    }

    if(ENCRYPT_FLAG == 0){
    	loga("Encryption is disabled for reconciliation");
    }

    peer_socket = accept(st->sd, NULL, NULL);
    if(peer_socket < 0){
    	log_error("peer socket coould not be established");
    	goto error;
    }
    loga("Spark downloader socket connection accepted"); //TODO: print information about the socket IP address.


    /* Initialize the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    /* Processing header for number of Keys */
    received_len = read(peer_socket, &tempInt, sizeof(int32_t));
    numberOfKeys = ntohl(tempInt);
    if( received_len < 1 ){
    	log_error("Error on receiving number of keys --> %s", strerror(errno));
    	goto error;
    }
    else if (numberOfKeys < 0) {
    	log_error("receive header not processed properly");
    	goto error;
    }
    else if (numberOfKeys == 0) {
    	log_error("no keys sent");
    	goto error;
    }
    loga("Expected number of keys: %d", numberOfKeys);

    /* Iterating around the keys */
    for(i=0; i<numberOfKeys; i++){
        memset(&redisKey[0], 0, sizeof(redisKey));
        memset(&newValue[0], 0, sizeof(newValue));
        memset(&oldValue[0], 0, sizeof(oldValue));

    	/* Receive the redisKey size in unencrypted format */
    	received_len = read(peer_socket, &tempInt, sizeof(int32_t));
    	keyLength = ntohl(tempInt);
    	if( received_len < 1 ){
    		log_error("Error on receiving key size --> %s", strerror(errno));
    		goto error;
    	}
    	/* Receive the newValue size in unencrypted format */
    	received_len = read(peer_socket, &tempInt, sizeof(int32_t));
    	newValueLength = ntohl(tempInt);
    	if( received_len < 1 ){
    		log_error("Error on receiving new value size --> %s", strerror(errno));
    		goto error;
    	}
    	/* Receive the oldValue size in unencrypted format */
    	received_len = read(peer_socket, &tempInt, sizeof(int32_t));
    	oldValueLength = ntohl(tempInt);
    	if( received_len < 1 ){
    		log_error("Error on receiving old value size --> %s", strerror(errno));
    		goto error;
    	}
    	log_info("key length: %d new value length: %d old value length: %d", keyLength, newValueLength, oldValueLength);


    	/* Receive the newValue in unencrypted format */
    	received_len = read(peer_socket, &redisKey, keyLength);
    	if( received_len < 1 ){
    		log_error("Error on receiving key --> %s", strerror(errno));
    		goto error;
    	}
    	/* Receive the newKey in unencrypted format */
    	received_len = read(peer_socket, &newValue, newValueLength);
    	if( received_len < 1 ){
    		log_error("Error on receiving new value --> %s", strerror(errno));
    		log_error("problem in key: %s -- seq: %d", redisKey, i+1);
    		goto error;
    	}
    	/* Receive the newKey in unencrypted format */
    	received_len = read(peer_socket, &oldValue, oldValueLength);
    	if( received_len < 0 ){
    		log_error("Error on receiving old value --> %s", redisKey, strerror(errno));
    		log_error("problem in key: %s -- seq: %d", redisKey, i+1);
    		goto error;
    	}
    	else if ( received_len == 0 ){
    		loga("old value was empty - no problem we continue");
    	}

    	loga("Received: %d of %d --- key: %s new value: %s old value: %s", i+1, numberOfKeys, redisKey, newValue, oldValue);


        char *argv[] = { "redis-cli -p 22122 COMPARESET"};
    	   char *envp[] =
    	    {
    	    	redisKey,
				newValue,
				oldValue,
    	    };
    	execve(argv[0], &argv[0], envp);

/*    	memset(&command[0], 0, sizeof(command));
    	sprintf(command, "redis-cli -p 22122 COMPARESET %s %s %s", redisKey, newValue, oldValue);

    	sys_ret = system(command);											//TODO: remove the system call to something faster.
    	if( sys_ret < 0 ){
    		log_error("Error on system call --> %s", strerror(errno));
    		goto error;
    	}
    	*/
    }

	/* Clean up */
	EVP_cleanup();
    ERR_free_strings();
	close(peer_socket);
	loga("entropy rcv closing socket gracefully.");
  	return;

error:
  	close(peer_socket);
  	loga("entropy rcv closing socket because of error.");
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
