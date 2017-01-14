/*
 * Dynomite - A thin, distributed replication layer for multi non-distributed storages.
 * Copyright (C) 2014 Netflix, Inc.
 */ 

/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "dyn_core.h"

#ifndef _DYN_SIGNAL_H_
#define _DYN_SIGNAL_H_


/**
 * @brief POSIX signal
 */
struct signal {
    int  signo;
    char *signame;
    int  flags;
    void (*handler)(int signo);
};

rstatus_t signal_init(void);
void signal_deinit(void);
void signal_handler(int signo);

#endif
