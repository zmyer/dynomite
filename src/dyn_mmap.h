/*
 * Dynomite - A thin, distributed replication layer for multi non-distributed storages.
 * Copyright (C) 2015 Netflix, Inc.
 */

/*
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

#include <sys/mman.h>
#include <fcntl.h>

#include "dyn_core.h"

#define DN_MMAP_PATH		"data_reconciliation.txt"
#define DYN_MMAP_SIZE       10000000	/* 10MB */

struct mapper {
	int mmap_fd;			/* file pointer */
	size_t counter;			/* counter of the amount bytes in the memory mapped file. Used to msync data if exceeds DYN_MMAP_SIZE */
	char *mmap;
};

struct mapper mm;

static struct mbuf * value_buf = NULL;

int dn_mmap_init(char *name);
int dn_mmap_deinit(void);
int dn_mmap_size(size_t counter);
