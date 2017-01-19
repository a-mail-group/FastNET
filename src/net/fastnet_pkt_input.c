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
#include <net/header/ip6hdr.h>
#include <net/header/ip6defs.h>
#include <net/header/layer4.h>
#include <net/packet_input.h>
#include <net/in_tlp.h>
#include <net/safe_packet.h>

#if 0
static void print_next_header(char ipv,int next_header){
		const char* x = "?";
		switch(next_header){
		case IP_PROTOCOL_HOPOPTS: x = "IP_PROTOCOL_HOPOPTS (Hop by hop)"; break;
		case IP_PROTOCOL_ICMP   : x = "IP_PROTOCOL_ICMP"; break;
		case IP_PROTOCOL_IGMP   : x = "IP_PROTOCOL_IGMP"; break;
		case IP_PROTOCOL_TCP    : x = "IP_PROTOCOL_TCP"; break;
		case IP_PROTOCOL_UDP    : x = "IP_PROTOCOL_UDP"; break;
		case IP_PROTOCOL_ROUTE  : x = "IP_PROTOCOL_GRE (IPv6 Routing header.)"; break;
		case IP_PROTOCOL_GRE    : x = "IP_PROTOCOL_GRE"; break;
		case IP_PROTOCOL_FRAG   : x = "IP_PROTOCOL_FRAG (IPv6 Fragment)"; break;
		case IP_PROTOCOL_ESP    : x = "IP_PROTOCOL_ESP (IPSec Encapsulated Payload)"; break;
		case IP_PROTOCOL_AH     : x = "IP_PROTOCOL_AH (IPSec Authentication Header)"; break;
		case IP_PROTOCOL_DSTOPTS: x = "IP_PROTOCOL_DSTOPTS (Destination Options)"; break;
		case IP_PROTOCOL_ICMP6  : x = "IP_PROTOCOL_ICMP6"; break;
		case IP_PROTOCOL_INVALID: x = "IP_PROTOCOL_INVALID (Reserved invalid by IANA)"; break;
		}
		NET_LOG("IPv%c packet: %s (%d)\n",ipv,x,next_header);
}
#endif

netpp_retcode_t fastnet_ip_input(odp_packet_t pkt){
	fnet_ip_header_t * __restrict__  ip;
	nif_t*                           nif = odp_packet_user_ptr(pkt);
	ipv4_addr_t                      dest_addr;
	int                              is_ours;
	uint8_t                          next_header;
	uint16_t                         cksum;
	
	ip = fastnet_safe_l3(pkt,sizeof(fnet_ip_header_t));
	if (odp_unlikely(ip == NULL)) return NETPP_DROP;
	
	if(odp_unlikely(FNET_IP_HEADER_GET_VERSION(ip)!=4)) return NETPP_DROP;
	cksum = fastnet_ipv4_hdr_checksum(pkt);
	if(odp_unlikely(cksum != 0)) return NETPP_DROP;
	
	dest_addr = ip->desination_addr;
	
	is_ours = fastnet_ip_isforme(nif->ipv4,dest_addr);
	
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

netpp_retcode_t fastnet_ip6_input(odp_packet_t pkt){
	fnet_ip6_header_t * __restrict__  ip6;
	nif_t*                            nif = odp_packet_user_ptr(pkt);
	netpp_retcode_t                   ret;
	ipv6_addr_t                       dest_addr;
	ipv6_addr_t                       src_addr;
	int                               is_ours;
	int                               next_header;
	int                               proto_idx;
	uint32_t                          havelen,shouldlen,offset;
	
	if(odp_unlikely(fastnet_ipv6_deactivated(nif->ipv6))) return NETPP_DROP;
	
	ip6 = fastnet_safe_l3(pkt,sizeof(fnet_ip6_header_t));
	if(odp_unlikely(ip6 == NULL)) return NETPP_DROP;
	
	/*
	 * Check the IPv6 header correctness.
	 */
	if(odp_unlikely((odp_be_to_cpu_32(ip6->version_tclass_flowl)>>28)!=6)) return NETPP_DROP;
	
	/*
	 * Get IPv6 addresses.
	 */
	src_addr  = ip6->source_addr;
	dest_addr = ip6->destination_addr;
	
	/*
	 * RFC-4291  2.7.  "Multicast Addresses"
	 * Multicast addresses must not be used as source addresses
	 * in IPv6 packets or appear in any Routing header.
	 */
	if(odp_unlikely(IP6_ADDR_IS_MULTICAST(src_addr))) return NETPP_DROP;
	
	/*
	 * Check, wether this IP address is targeted at us.
	 */
	is_ours = fastnet_ipv6_addr_is_self(nif->ipv6,&dest_addr);
	
	if(is_ours){
		next_header = ip6->next_header;
		
		shouldlen = odp_be_to_cpu_16(ip6->length);
		
		ip6 = NULL;
		offset = odp_packet_l3_offset(pkt)+sizeof(fnet_ip6_header_t);
		odp_packet_l4_offset_set(pkt,offset);
		havelen = odp_packet_len(pkt)-offset;
		
		if(odp_unlikely(havelen>shouldlen)) odp_packet_pull_tail(pkt,havelen-shouldlen);
		else if(odp_unlikely(havelen<shouldlen)) return NETPP_DROP;
		
		ret = NETPP_CONTINUE;
		while(ret==NETPP_CONTINUE && next_header<IP_NO_PROTOCOL){
			proto_idx = fn_in6_protocol_idx[next_header];
			ret = fn_in_protocols[proto_idx].in6_hook(pkt,&next_header,proto_idx);
		}
		return ret;
	}
	
	/* TODO: forward */
	return NETPP_DROP;
}

netpp_retcode_t fastnet_classified_input(odp_packet_t pkt){
	if(odp_packet_has_ipv4(pkt))
		return fastnet_ip_input(pkt);
	
	if(odp_packet_has_arp(pkt))
		return fastnet_arp_input(pkt);
	
	if(odp_packet_has_ipv6(pkt))
		return fastnet_ip6_input(pkt);
	return NETPP_DROP;
}

netpp_retcode_t fastnet_raw_input(odp_packet_t pkt){
	return NETPP_DROP;
}

