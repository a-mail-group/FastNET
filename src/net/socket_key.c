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
#include <net/socket_key.h>
#include <net/header/iphdr.h>
#include <net/header/ip6hdr.h>
#include <net/safe_packet.h>

typedef struct ODP_PACKED {
	uint16_t src;
	uint16_t dst;
} PORTS_T;

/*
 * Obtains the IP-level fields of the socket key.
 *
 * The fields src_port, dst_port and layer4_version are left to be filled by the callee.
 */
netpp_retcode_t fastnet_socket_key_obtain_ip(odp_packet_t pkt, socket_key_t *key){
	fnet_ip_header_t*  ip;
	fnet_ip6_header_t* ip6;
	
	key->nif = odp_packet_user_ptr(pkt);
	
	if(odp_packet_has_ipv4(pkt)){
		ip = fastnet_safe_l3(pkt,sizeof(fnet_ip_header_t));
		if(odp_unlikely(ip!=NULL)) return NETPP_DROP;
		key->src_ip = (ipv6_addr_t){.addr32 = {0,0,0,ip->source_addr}};
		key->dst_ip = (ipv6_addr_t){.addr32 = {0,0,0,ip->destination_addr}};
		key->layer3_version = 4;
	}else{
		ip6 = fastnet_safe_l3(pkt,sizeof(fnet_ip6_header_t));
		if(odp_unlikely(ip6!=NULL)) return NETPP_DROP;
		key->src_ip = ip6->source_addr;
		key->dst_ip = ip6->destination_addr;
		key->layer3_version = 6;
	}
	
	return NETPP_CONTINUE;
}

/*
 * Obtains the IP-level fields of the socket key, and the ports.
 *
 * The field layer4_version is left to be filled by the callee.
 */
netpp_retcode_t fastnet_socket_key_obtain(odp_packet_t pkt, socket_key_t *key){
	fnet_ip_header_t*  ip;
	fnet_ip6_header_t* ip6;
	PORTS_T ports;
	
	key->nif = odp_packet_user_ptr(pkt);
	
	if(odp_packet_has_ipv4(pkt)){
		ip = fastnet_safe_l3(pkt,sizeof(fnet_ip_header_t));
		if(odp_unlikely(ip!=NULL)) return NETPP_DROP;
		key->src_ip = (ipv6_addr_t){.addr32 = {0,0,0,ip->source_addr}};
		key->dst_ip = (ipv6_addr_t){.addr32 = {0,0,0,ip->destination_addr}};
		key->layer3_version = 4;
	}else{
		ip6 = fastnet_safe_l3(pkt,sizeof(fnet_ip6_header_t));
		if(odp_unlikely(ip6!=NULL)) return NETPP_DROP;
		key->src_ip = ip6->source_addr;
		key->dst_ip = ip6->destination_addr;
		key->layer3_version = 6;
	}
	if(odp_packet_copy_to_mem(pkt,odp_packet_l4_offset(pkt),sizeof(ports),&ports)) {
		ports = (PORTS_T){0,0};
	}
	key->src_port = ports.src;
	key->dst_port = ports.dst;
	
	return NETPP_CONTINUE;
}

