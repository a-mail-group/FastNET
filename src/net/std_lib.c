/*
 *   Copyright 2016 Simon Schmidt
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
#include <stdlib.h>
#include <net/std_lib.h>
#include <net/std_defs.h>

typedef const char* const_char_p;

static inline const_char_p
notnull(const_char_p ptr){
	if(ptr == NULL) return "";
	return ptr;
}

static fastnet_size_t
get_string_sizes(fastnet_size_t size, const const_char_p* strs){
	const_char_p str;
	for(;;){
		str = *strs++;
		if(!str) break;
		while(*str++) size++;
	}
	return size;
}
static void
string_concat(char* __restrict__ dest,const const_char_p* strs){
	const char* __restrict__ str;
	for(;;){
		str = *strs++;
		if(!str) break;
		while(*str) *(dest++) = *(str++);
	}
	*dest = 0;
}

const char* fastnet_dup_concat3(const char* arg1,const char* arg2,const char* arg3){
	const const_char_p args[]={
		notnull(arg1),
		notnull(arg2),
		notnull(arg3),
		NULL,
	};
	/*
	 * The area we need to allocate is the size of all strings + 1 ("sizes + 1").
	 * However, we allocate "sizes + 4" for safety. Just in case.
	 */
	fastnet_size_t size = get_string_sizes(4,args);
	char* ptr = fastnet_malloc(size);
	if(ptr == NULL) return NULL;
	string_concat(ptr,args);
	return ptr;
}

