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

#include "dyn_core.h"
#include "dyn_mmap.h"

int
dn_mmap_init(char *name)
{

	if(name == NULL || !strlen(name)) {
		return DN_ERROR;
	} else {
		/*
		 * O_RDWR: open for writing and reading
		 * O_CREATE: create the file if it does not exist
		 * O_TRUNC: if the file exists then discard its previous content, reducing to an empty file
		 */
		mm.mmap_fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
		mm.counter = 0 ;
		if(mm.mmap_fd < 0) {
			log_stderr("opening memory mapped backend timestamp file '%s' failed: %s", name,
				strerror(errno));
		        return DN_ERROR;
		}
		mm.mmap = (char*)mmap(NULL, DYN_MMAP_SIZE, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, mm.mmap_fd, 0);
		if(mm.mmap == MAP_FAILED){
			log_stderr("memory map failed: %s", strerror(errno));
			close(mm.mmap_fd);
			return DN_ERROR;
		}
		else{
			log_stderr("memory map success: %s", strerror(errno));
		}
	}

	return DN_OK;
}

int
dn_mmap_deinit(void)
{

    if(munmap(mm.mmap, DYN_MMAP_SIZE)==DN_ERROR) {
    	log_stderr("unmapping the memory mapped file failed", strerror(errno));
    	return DN_ERROR;
    }
    if (mm.mmap_fd < 0 || mm.mmap_fd == STDERR_FILENO) {
    	log_stderr("closing memory mapped file pointer failed", strerror(errno));
    	return DN_ERROR;
    }
    close(mm.mmap_fd);
    return DN_OK;
}

int
dn_mmap_size(size_t counter)
{
	size_t temp_counter = mm.counter;
	mm.counter += counter;
	if(mm.counter >= DYN_MMAP_SIZE){
		/* MS_SYNC: the data is actually written to disk
		 * MS_ASYNC: begin the synchronization, but do not wait to be complete
		 */
		if(msync(mm.mmap_fd, temp_counter, MS_ASYNC)<0){
			return DN_ERROR;
		}
		mm.counter = counter;
	}
	return DN_ERROR;
}
