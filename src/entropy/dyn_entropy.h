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



#include "dyn_core.h"

#define ENTROPY_SND_ADDR      "0.0.0.0"		//TODO: pass later on IP address as configuration
#define ENTROPY_SND_PORT      8105

#define ENTROPY_RCV_ADDR      "0.0.0.0"		//TODO: pass later on IP address as configuration
#define ENTROPY_RCV_PORT	  8106

#define ENCRYPT_FLAG			0
#define COMPRESS_FLAG			0
#define CIPHER_SIZE				1024
#define BUFFER_SIZE				512
#define HEADER_SIZE				512

#define AOF_TO_SEND		"/mnt/data/nfredis/appendonly.aof"	/* later on add as command line property */
#define GZIP_TO_SEND 	"/mnt/data/appendonly0.aof.gz"


/* this indicates if the key and iv have been loaded */
short keyIVLoaded;

/* Structure for sending AOF to Spark Cluster */
struct entropy {
    struct context           *ctx;
    uint16_t                  port;           		  /* port */
    struct string             addr;           		  /* address */
    int64_t                   entropy_ts;     		  /* timestamp of dynomite */
    pthread_t                 tid;            		  /* aggregator thread */
    int                       interval;       		  /* entropy aggregation interval */
    int                       sd;             		  /* socket descriptor */
    int 					  redis_sd;				  /* Redis socket descriptor for AOF */
    struct string	          recon_key_file;		  /* file with Key encryption in reconciliation */
    struct string             recon_iv_file;		  /* file with Initialization Vector encryption in reconciliation */
};


struct entropy *entropy_snd_init(uint16_t entropy_port, char *entropy_ip, struct context *ctx);
struct entropy *entropy_rcv_init(uint16_t entropy_port, char *entropy_ip, struct context *ctx);

void entropy_conn_destroy(struct entropy *cn);

int entropy_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);

int entropy_decrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);

rstatus_t entropy_listen(struct entropy *cn);
rstatus_t entropy_key_iv_load();

