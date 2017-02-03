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
#include <net/ip_next_hop.h>
#include <net/ip6_next_hop.h>
#include <net/checksum.h>
#include <net/packet_output.h>

enum {
	/*
	 * Ethernet header (14 bytes),
	 * VLAN tag(4 bytes),
	 */
	ETHERNET_HEADER_LEN = 14 + 4,
};

static uint16_t wnd_to_16(uint32_t wnd){
	if(wnd<0xFFFF)return (uint16_t)wnd;
	return 0xFFFF;
}

netpp_retcode_t fastnet_tcp_output_flags_wnd(odp_packet_t pkt,socket_key_t *key,uint32_t seq,uint32_t ack,uint32_t wnd,uint16_t flags){
	netpp_retcode_t   ret;
	odp_pool_t        pool;
	fnet_tcp_header_t header;
	union{
	fnet_ip6_header_t ip6;
	fnet_ip_header_t  ip;
	} ihdr;
	uint32_t          ihdrlen, full_len, cur_len;
	int               is_alloc;
	
	if(key->layer3_version==0x66){
		/* IPv6 */
		ihdrlen = sizeof(fnet_ip6_header_t);
	}else{
		/* IPv4 */
		ihdrlen = sizeof(fnet_ip_header_t);
	}
	
	full_len = ETHERNET_HEADER_LEN + sizeof(fnet_tcp_header_t) + ihdrlen;
	
	is_alloc = pkt==ODP_PACKET_INVALID;
	
	if(is_alloc){
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
	header.hdrlength__flags = odp_cpu_to_be_16(0x5000|flags);
	header.window = odp_cpu_to_be_16(wnd_to_16(wnd));
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
		ret = fastnet_ip6_output(pkt,NULL);
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
		ret = fastnet_ip_output(pkt,NULL);
	}
	
	if(is_alloc && (ret!=NETPP_CONSUMED))
		odp_packet_free(pkt);
	
	return ret;
}

netpp_retcode_t fastnet_tcp_output_flags(odp_packet_t pkt,socket_key_t *key,uint32_t seq,uint32_t ack,uint16_t flags){
	return fastnet_tcp_output_flags_wnd(pkt,key,seq,ack,0,flags);
}

netpp_retcode_t fastnet_tcp_sendout_ll(odp_packet_t pkt,fastnet_tcp_pcb_t* pcb,nif_t* nif,uint16_t length) {
	socket_key_t* key;
	uint16_t field16;
	
	key = &(((fastnet_sockstruct_t*)pcb)->key);
	
	/*
	 * Update the IPv[46] length field.
	 */
	if(odp_packet_has_ipv4(pcb->tcpiphdr.buf)){
		field16 = odp_cpu_to_be_16(length+sizeof(fnet_ip_header_t));
		odp_packet_copy_from_mem(pkt,odp_packet_l3_offset(pkt)+IPV4_HDR_LENGTH_OFFSET,2,&field16);
		
		field16 = fastnet_ip4_checksum(pkt,key->src_ip.addr32[3],key->dst_ip.addr32[3],IP_PROTOCOL_TCP);
	}else{
		field16 = odp_cpu_to_be_16(length);
		odp_packet_copy_from_mem(pkt,odp_packet_l3_offset(pkt)+IPV6_HDR_LENGTH_OFFSET,2,&field16);
		field16 = fastnet_ip6_checksum(pkt,key->src_ip,key->dst_ip,IP_PROTOCOL_TCP);
	}
	
	odp_packet_copy_from_mem(pkt,odp_packet_l4_offset(pkt)+TCP_HDR_CHECKSUM_OFFSET,2,&field16);
	
	if(nif){
		if(odp_packet_has_ipv4(pcb->tcpiphdr.buf)){
			field16 = fastnet_ipv4_hdr_checksum(pkt);
			
			odp_packet_copy_from_mem(pkt,odp_packet_l3_offset(pkt)+IPV4_HDR_CHECKSUM_OFFSET,2,&field16);
		}
		/* XXX whats about loopback? */
		return fastnet_pkt_output(pkt,nif);
	}else{
		if(odp_packet_has_ipv4(pcb->tcpiphdr.buf)){
			return fastnet_ip_output(pkt,NULL);
		}else{
			return fastnet_ip6_output(pkt,NULL);
		}
	}
}

static int tmo_exceed(odp_time_t diff,uint32_t tmo_ms){
	register uint32_t tmo = tmo_ms/1000;
	if(tmo<diff.tv_sec) return 1;
	if(tmo>diff.tv_sec) return 0;
	return (tmo_ms%1000)<(diff.tv_nsec/1000000);
}

int fastnet_tcp_add_header(odp_packet_t pkt,fastnet_tcp_pcb_t* __restrict__ pcb,odp_time_t now,nif_t** nifp){
	nif_t* nif = NULL;
	uint32_t begin,end,l3p,timeout;
	odp_time_t tmdiff;
	
	timeout = pcb->tcpiphdr.eth_lifetime;
	if(timeout && tmo_exceed(odp_time_diff(now,pcb->tcpiphdr.eth_tstamp),timeout)) timeout = 0;
	
	if(timeout){
		nif = pcb->tcpiphdr.eth_nif;
	} /* TODO query. */
	
	end = odp_packet_l4_offset(pcb->tcpiphdr.buf)+sizeof(fnet_tcp_header_t);
	l3p = odp_packet_l3_offset(pcb->tcpiphdr.buf);
	if(nif) begin = odp_packet_l2_offset(pcb->tcpiphdr.buf);
	else    begin = l3p;
	
	end -= begin;
	l3p -= begin;
	
	if(odp_unlikely(!odp_packet_push_head(pkt,end))) return 1;
	
	odp_packet_copy_from_pkt(pkt,0, pcb->tcpiphdr.buf, begin, end);
	odp_packet_l4_offset_set(pkt,end-sizeof(fnet_tcp_header_t));
	odp_packet_l3_offset_set(pkt,l3p);
	odp_packet_l2_offset_set(pkt,0);
	*nifp = nif;
	return 0;
}


/*
 * This function constructs a TCP/IP header in a given buffer (type is odp_packet_t).
 * odp_packet_l4_offset() must be set.
 */
void fastnet_tcp_segmout_create_header_buf(odp_packet_t pkt,socket_key_t *key){
	fnet_tcp_header_t header;
	union{
	fnet_ip6_header_t ip6;
	fnet_ip_header_t  ip;
	} ihdr;
	
	
	if(key->layer3_version==0x66){
		/* IPv6 */
		ihdr.ip6.version_tclass_flowl  = odp_cpu_to_be_32(0x60000000); // tclass = 0
		ihdr.ip6.length                = odp_cpu_to_be_16(sizeof(header));
		ihdr.ip6.next_header           = IP_PROTOCOL_TCP;
		ihdr.ip6.hop_limit             = 64;
		
		/*
		 * Source and Destination addresses/ports must be swapped.
		 */
		ihdr.ip6.source_addr           = key->dst_ip;
		ihdr.ip6.destination_addr      = key->src_ip;
		odp_packet_l3_offset_set(pkt,odp_packet_l4_offset(pkt)-sizeof(ihdr.ip6));
		odp_packet_copy_from_mem(pkt,odp_packet_l3_offset(pkt),sizeof(ihdr.ip6),&ihdr.ip6);
		odp_packet_has_ipv4_set(pkt,0);
		odp_packet_has_ipv6_set(pkt,1);
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
		
		/*
		 * Source and Destination addresses/ports must be swapped.
		 */
		ihdr.ip.source_addr            = key->dst_ip.addr32[4];
		ihdr.ip.destination_addr       = key->src_ip.addr32[4];
		odp_packet_l3_offset_set(pkt,odp_packet_l4_offset(pkt)-sizeof(ihdr.ip));
		odp_packet_copy_from_mem(pkt,odp_packet_l3_offset(pkt),sizeof(ihdr.ip),&ihdr.ip);
		odp_packet_has_ipv4_set(pkt,1);
		odp_packet_has_ipv6_set(pkt,0);
	}
	
	/*
	 * Source and Destination addresses/ports must be swapped.
	 */
	header.source_port      = key->dst_port;
	header.destination_port = key->src_port;
	header.sequence_number  = 0;
	header.ack_number       = 0;
	header.hdrlength__flags = 0;
	header.window           = 0;
	header.checksum         = 0;
	header.urgent_ptr       = 0;
	odp_packet_copy_from_mem(pkt,odp_packet_l4_offset(pkt),sizeof(header),&header);
}


