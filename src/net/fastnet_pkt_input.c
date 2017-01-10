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
#include <net/nif.h>
#include <net/types.h>
#include <net/_config.h>
#include <net/header/iphdr.h>
#include <net/packet_input.h>
#include <net/in_tlp.h>

netpp_retcode_t fastnet_ip_input(odp_packet_t pkt){
	fnet_ip_header_t * __restrict__  ip;
	nif_t*                           nif = odp_packet_user_ptr(pkt);
	ipv4_addr_t                      dest_addr;
	int                              is_ours;
	uint8_t                          next_header;
	
	ip = odp_packet_l3_ptr(pkt,NULL);
	if (odp_unlikely(ip == NULL)) return NETPP_DROP;
	
	if(odp_unlikely(FNET_IP_HEADER_GET_VERSION(ip)!=4)) return NETPP_DROP;
	/* TODO: checksum. */
	
	dest_addr = ip->desination_addr;
	
	is_ours = fastnet_ip_ishost(nif->ipv4,dest_addr);
	
	if(is_ours){
		odp_packet_l4_offset_set(pkt,odp_packet_l3_offset(pkt)+(FNET_IP_HEADER_GET_HEADER_LENGTH(ip)*4));
		
		next_header = ip->protocol;
		
		ip = NULL;
		fastnet_ip_reass(&pkt);
		if(pkt==ODP_PACKET_INVALID) return NETPP_CONSUMED;
		
		return fn_in_protocols[fn_in4_protocol_idx[next_header]].in_hook(pkt);
	}
	
	/* TODO: forward */
	return NETPP_DROP;
}

netpp_retcode_t fastnet_classified_input(odp_packet_t pkt){
	if(odp_packet_has_ipv4(pkt))
		return fastnet_ip_input(pkt);
	
	//if(odp_packet_has_ipv6(pkt)) NET_LOG("Has IPv6 packet!\n");
	return NETPP_DROP;
}

netpp_retcode_t fastnet_raw_input(odp_packet_t pkt){
	return NETPP_DROP;
}

