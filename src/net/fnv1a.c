/*
 *   Copyright 2017 Simon Schmidt
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
#include <net/fnv1a.h>

static const uint32_t FNV_prime = 16777619U;
static const uint32_t FNV_basis = 2166136261U;

uint32_t fastnet_fnv1a_init(){ return FNV_basis; }
uint32_t fastnet_fnv1a(uint32_t hash,const uint8_t* data,unsigned len){
	for(;len;len--,data++){
		hash ^= *data;
		hash *= FNV_prime;
	}
	return hash;
}

