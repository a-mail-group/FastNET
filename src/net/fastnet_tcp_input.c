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
#include <net/header/tcphdr.h>
#include <net/header/iphdr.h>
#include <net/header/ip6hdr.h>
#include <net/safe_packet.h>
#include <net/in_tlp.h>

#include <net/socket_key.h>

#include <net/header/layer4.h>

static
void get_socket_key_ip(odp_packet_t pkt, socket_key_t *key){
	fnet_ip_header_t*  ip;
	fnet_ip6_header_t* ip6;
	
	key->nif = odp_packet_user_ptr(pkt);
	
	if(odp_packet_has_ipv4(pkt)){
		ip = fastnet_safe_l3(pkt,sizeof(fnet_ip_header_t));
		key->src.ip = (ipv6_addr_t){.addr32 = {0,0,0,ip->source_addr}};
		key->dst.ip = (ipv6_addr_t){.addr32 = {0,0,0,ip->destination_addr}};
		key->layer3_version = 4;
	}else{
		ip6 = fastnet_safe_l3(pkt,sizeof(fnet_ip6_header_t));
		key->src.ip = ip6->source_addr;
		key->dst.ip = ip6->destination_addr;
		key->layer3_version = 6;
	}
}

netpp_retcode_t fastnet_tcp_input(odp_packet_t pkt){
	socket_key_t key;
	fnet_tcp_header_t* th = odp_packet_l4_ptr(pkt,NULL);
	key.layer4_version = IP_PROTOCOL_TCP;
	key.src.port = th->source_port;
	key.dst.port = th->destination_port;
	
	NET_LOG("TCP segment: %d->%d\n",(int)odp_be_to_cpu_16(th->source_port),(int)odp_be_to_cpu_16(th->destination_port));
	return NETPP_DROP;
}



