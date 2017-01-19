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
#pragma once

#include <odp_api.h>

/*
 * Safety feature:
 * When we get a header, we check for the size.
 */

static inline
void* fastnet_safe_offset(odp_packet_t pkt,uint32_t offset,uint32_t req){
	uint32_t size;
	void* ret = odp_packet_offset(pkt,offset,&size,(odp_packet_seg_t*)0);
	return  odp_unlikely(size<req) ? 0 : ret;
}

static inline
void* fastnet_safe_l2(odp_packet_t pkt,uint32_t req){
	uint32_t size;
	void* ret = odp_packet_l2_ptr(pkt,&size);
	return  odp_unlikely(size<req) ? 0 : ret;
}

static inline
void* fastnet_safe_l3(odp_packet_t pkt,uint32_t req){
	uint32_t size;
	void* ret = odp_packet_l3_ptr(pkt,&size);
	return  odp_unlikely(size<req) ? 0 : ret;
}


static inline
void* fastnet_safe_l4(odp_packet_t pkt,uint32_t req){
	uint32_t size;
	void* ret = odp_packet_l4_ptr(pkt,&size);
	return  odp_unlikely(size<req) ? 0 : ret;
}

