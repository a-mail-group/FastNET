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
#include <net/ipv4.h>
#include <net/header/iphdr.h>

void fastnet_ip_reass(odp_packet_t* __restrict__ pkt){
	uint16_t frag = odp_be_to_cpu_16(((fnet_ip_header_t *)odp_packet_l3_ptr(*pkt,NULL))->flags_fragment_offset);
	
	/* TODO: reass. */
	if(odp_unlikely(frag & ~FNET_IP_DF)){
		odp_packet_free(*pkt);
		*pkt = ODP_PACKET_INVALID;
	}
	
}