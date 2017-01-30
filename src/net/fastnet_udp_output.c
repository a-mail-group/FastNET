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
#include <net/udp.h>
#include <net/header/iphdr.h>
#include <net/header/ip6hdr.h>
#include <net/header/udphdr.h>
#include <net/header/layer4.h>
//#include <net/in_tlp.h>
#include <net/ip_next_hop.h>
#include <net/checksum.h>

typedef struct ODP_PACKED {
	fnet_ip_header_t  ip;
	fnet_udp_header_t udp;
} udpiphdr_t;

typedef struct ODP_PACKED {
	fnet_ip6_header_t ip6;
	fnet_udp_header_t udp;
} udpip6hdr_t;


static inline
netpp_retcode_t udp_set_head(odp_packet_t pkt, fastnet_ip_pair_t addrs, uint16_t srcport, uint16_t dstport, odp_bool_t isipv6,uint32_t pktlen){
	int isbc;
	udpiphdr_t*  __restrict__ uh4;
	udpip6hdr_t* __restrict__ uh6;
	/*
	 * 0xffff - 20 => 0xffeb
	 */
	
	if(odp_unlikely(pktlen>0xffeb)){
		NET_LOG("unable to send length > %d: pktlen = %d",0xffeb,(int)pktlen);
		return NETPP_DROP;
	}
	
	odp_packet_l3_offset_set(pkt,0);
	if(isipv6){
		uh6 = odp_packet_push_head(pkt,sizeof(udpip6hdr_t));
		uh6->udp.source_port           = srcport;
		uh6->udp.destination_port      = dstport;
		uh6->udp.length                = odp_cpu_to_be_16(pktlen);
		uh6->udp.checksum              = fastnet_ip6_ph(addrs.ipv6->src,addrs.ipv6->dst,IP_PROTOCOL_UDP);
		
		/*
		 * The IP-version is 6, the Traffic Class is 0x00 and the
		 * Flow Label is 0x00000 (will be set by the IPv6 stack).
		 */
		uh6->ip6.version_tclass_flowl  = odp_cpu_to_be_32(0x60000000); // tclass = 0
		uh6->ip6.length                = uh6->udp.length;
		uh6->ip6.next_header           = IP_PROTOCOL_UDP;
		uh6->ip6.hop_limit             = FNET_UDP_TTL;
		uh6->ip6.source_addr           = addrs.ipv6->src;
		uh6->ip6.destination_addr      = addrs.ipv6->dst;
		odp_packet_l4_offset_set(pkt,sizeof(fnet_ip6_header_t));
	}else{
		isbc = IP4_ADDR_IS_MULTICAST(addrs.ipv4.dst);
		uh4 = odp_packet_push_head(pkt,sizeof(udpiphdr_t));
		uh4->udp.source_port           = srcport;
		uh4->udp.destination_port      = dstport;
		uh4->udp.length                = odp_cpu_to_be_16(pktlen);
		uh4->udp.checksum              = fastnet_ip_ph(addrs.ipv4.src,addrs.ipv4.dst,IP_PROTOCOL_UDP);
		
		/*
		 * The IP version is 4 and the Default IP header length is 5.
		 * Packet into a single byte, it is 0x45.
		 */
		uh4->ip.version__header_length = 0x45;
		uh4->ip.tos                    = FNET_IP_TOS_NORMAL;
		uh4->ip.total_length           = odp_cpu_to_be_16(pktlen+sizeof(fnet_ip_header_t));
		uh4->ip.id                     = 0;
		uh4->ip.flags_fragment_offset  = 0;
		uh4->ip.ttl                    = isbc ? FNET_UDP_TTL_MULTICAST : FNET_UDP_TTL;
		uh4->ip.protocol               = IP_PROTOCOL_UDP;
		uh4->ip.checksum               = 0;
		uh4->ip.source_addr            = addrs.ipv4.src;
		uh4->ip.destination_addr       = addrs.ipv4.dst;
		odp_packet_l4_offset_set(pkt,sizeof(fnet_ip_header_t));
	}
	return NETPP_CONTINUE;
}

netpp_retcode_t fastnet_udp_output(odp_packet_t pkt, fastnet_ip_pair_t addrs, uint16_t srcport, uint16_t dstport, odp_bool_t isipv6){
	uint32_t pktlen;
	netpp_retcode_t ret;
	fnet_udp_header_t* uh;
	
	pktlen = odp_packet_len(pkt)+8;
	
	ret = udp_set_head(pkt,addrs,srcport,dstport,isipv6,pktlen);
	if(odp_unlikely(ret!=NETPP_CONTINUE)) return ret;
	
	uh = odp_packet_l4_ptr(pkt,NULL);
	uh->checksum = fastnet_checksum(pkt,odp_packet_l4_offset(pkt),pktlen,odp_packet_user_ptr(pkt),0);
	/* XXX: checksum offload support is deferred. */
	
	if(isipv6){
		/* TODO: IPv6 */
		return NETPP_DROP;
	}else{
		return fastnet_ip_output(pkt,NULL);
	}
}

