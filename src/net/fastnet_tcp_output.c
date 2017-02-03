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
#include <net/config.h>
#include <net/header/tcphdr.h>
#include <net/header/iphdr.h>
#include <net/header/ip6hdr.h>
#include <net/socket_tcp.h>
#include <net/header/layer4.h>

enum {
	/*
	 * Ethernet header (14 bytes),
	 * VLAN tag(4 bytes),
	 */
	ETHERNET_HEADER_LEN = 14 + 4,
};

netpp_retcode_t fastnet_tcp_output_flags(odp_packet_t pkt,socket_key_t *key,uint32_t seq,uint32_t ack,uint16_t flags){
	odp_pool_t        pool;
	fnet_tcp_header_t header;
	union{
	fnet_ip6_header_t ip6;
	fnet_ip_header_t  ip;
	} ihdr;
	uint32_t          ihdrlen, full_len, cur_len;
	
	if(key->layer3_version==0x66){
		/* IPv6 */
		ihdrlen = sizeof(fnet_ip6_header_t);
	}else{
		/* IPv4 */
		ihdrlen = sizeof(fnet_ip_header_t);
	}
	
	full_len = ETHERNET_HEADER_LEN + sizeof(fnet_tcp_header_t) + ihdrlen;
	
	if(pkt==ODP_PACKET_INVALID){
		pool = odp_pool_lookup("fn_pktout");
		if(odp_unlikely(pool == ODP_POOL_INVALID)) return NETPP_DROP;
		
		pkt  = odp_packet_alloc(pool,full_len );
		if(odp_unlikely(pkt == ODP_PACKET_INVALID)) return NETPP_DROP;
	}else{
		cur_len = odp_packet_len(pkt);
		if(cur_len<full_len){
			if(odp_unlikely(odp_packet_push_tail(pkt,full_len-cur_len)==NULL)) return NETPP_DROP;
		}else if(cur_len>full_len){
			odp_packet_pull_tail(pkt,cur_len-full_len);
		}
	}
	
	/* Source and Destination addresses/ports must be swapped. */
	header.source_port = key->dst_port;
	header.destination_port = key->src_port;
	header.sequence_number = odp_cpu_to_be_32(seq);
	header.ack_number = odp_cpu_to_be_32(ack);
	header.hdrlength__flags = odp_cpu_to_be_32(0x5000|flags);
	header.window = 0;
	header.checksum = 0;
	header.urgent_ptr = 0;
	odp_packet_l3_offset_set(pkt,ETHERNET_HEADER_LEN);
	odp_packet_l4_offset_set(pkt,ETHERNET_HEADER_LEN+ihdrlen);
	odp_packet_copy_from_mem(pkt,ETHERNET_HEADER_LEN+ihdrlen,sizeof(header),&header);
	
	
	
	if(key->layer3_version==0x66){
		/* IPv6 */
		ihdr.ip6.version_tclass_flowl  = odp_cpu_to_be_32(0x60000000); // tclass = 0
		ihdr.ip6.length                = odp_cpu_to_be_16(sizeof(header));
		ihdr.ip6.next_header           = IP_PROTOCOL_TCP;
		ihdr.ip6.hop_limit             = 64;
		ihdr.ip6.source_addr           = key->dst_ip;
		ihdr.ip6.destination_addr      = key->src_ip;
		odp_packet_copy_from_mem(pkt,ETHERNET_HEADER_LEN,sizeof(ihdr.ip6),&ihdr.ip6);
	}else{
		/* IPv4 */
		ihdr.ip.version__header_length = 0x45;
		ihdr.ip.tos                    = FNET_IP_TOS_NORMAL;
		ihdr.ip.total_length           = odp_cpu_to_be_16(sizeof(header)+sizeof(fnet_ip_header_t));
		ihdr.ip.id                     = 0;
		ihdr.ip.flags_fragment_offset  = 0;
		ihdr.ip.ttl                    = 64;
		ihdr.ip.protocol               = IP_PROTOCOL_TCP;
		ihdr.ip.checksum               = 0;
		ihdr.ip.source_addr            = key->dst_ip.addr32[4];
		ihdr.ip.destination_addr       = key->src_ip.addr32[4];
		odp_packet_copy_from_mem(pkt,ETHERNET_HEADER_LEN,sizeof(ihdr.ip),&ihdr.ip);
	}
	
	return NETPP_DROP;
}


netpp_retcode_t fastnet_tcp_output(odp_packet_t pkt,uint16_t seq){
	return NETPP_DROP;
}

