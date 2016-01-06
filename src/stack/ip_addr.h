/*
 *
 * Copyright 2016 Simon Schmidt
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#pragma once

#include <odp.h>

typedef union ODP_PACKED {
	uint32be_t as_odp;
	uint8_t addr[4];
} fstn_ipv4_t;

typedef struct ODP_PACKED {
	uint8_t addr[16];
} fstn_ipv6_t;

#define FSTN_IPV6_CAST(ip) (*((fstn_ipv6_t*)(ip)))

static inline fstn_ipv4_t fstn_ipv4_cast(uint32be_t ip){
	fstn_ipv4_t result;
	result.as_odp = ip;
	return result;
}

#define FSTN_IPV6_EQUALS(a,b)  fstn_ipv6_equals((uint64_t*)(a).addr,(uint64_t*)(b).addr)

static inline int fstn_ipv6_equals(uint64_t *a,uint64_t *b){
	return (a[0]==b[0]) && (a[1]==b[1]);
}

