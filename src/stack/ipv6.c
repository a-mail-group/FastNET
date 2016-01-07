/*
 *
 * Copyright 2016 Simon Schmidt
 * Copyright 2011-2015 by Andrey Butok. FNET Community.
 * Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
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

#include "ipv6.h"

#include "eth.h"

#include "tcp.h"
#include "udp.h"
#include <odp/helper/ip.h>
#include "ip_addr_ext.h"
#include "addrtable.h"
#include "generic.h"

/*
 * This file is derived from FNET as of version 3.0.0
 */

/* For IPv6 */
#define FNET_ETH_MULTICAST_IP6_TO_MAC(ip6_addr, mac_addr)        \
            do{   \
                (mac_addr)[0] = 0x33U;               \
                (mac_addr)[1] = 0x33U;               \
                (mac_addr)[2] = (ip6_addr).addr[12]; \
                (mac_addr)[3] = (ip6_addr).addr[13]; \
                (mac_addr)[4] = (ip6_addr).addr[14]; \
                (mac_addr)[5] = (ip6_addr).addr[15];  \
            }while(0)


static inline int fstn_ipv6_is_my_ip(thr_s* thr,fstn_ipv6_t ip){
	ipv6_table_s* tab = thr->netif->ipv6_table;
	uint64_t h = fstn_fnv1a(ip.addr,ip.addr+16);
	uint32_t h1 =  h     %(tab->num);
	uint32_t h2 = (h>>16)%(tab->num);
	return FSTN_IPV6_EQUALS(tab->tab[h1],ip) || FSTN_IPV6_EQUALS(tab->tab[h2],ip);
}


/*
 * @brief processes an IPv6 Datagram
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function processes an IPv6 Datagram.
 */
void fstn_ipv6_input(odp_packet_t pkt, thr_s* thr){
	fstn_ipv6_t src,dst;
	uint32_t len,payload_len,payload_off;
	odph_ipv6hdr_t* hdr = odp_packet_l3_ptr(pkt,&len);
	odph_ethhdr_t* eth_hdr = odp_packet_l2_ptr(pkt,NULL);
	
	if(odp_unlikely( len < ODPH_IPV6HDR_LEN ))
		goto DISCARD;

	src = FSTN_IPV6_CAST(hdr->src_addr);
	dst = FSTN_IPV6_CAST(hdr->dst_addr);

	if(odp_unlikely(FNET_IP6_ADDR_IS_MULTICAST(src)))
		goto DISCARD;

	/* Is it for me? */
	if(odp_unlikely(!(
		fstn_ipv6_is_my_ip(thr,dst) ||
		(FNET_IP6_ADDR_IS_MULTICAST(dst))
		)))
		goto DISCARD;

	payload_off = odp_packet_l4_offset(pkt);
	len = odp_packet_len(pkt)-payload_off;

	payload_len = odp_be_to_cpu_16(hdr->payload_len);
	
	if(odp_unlikely( len < payload_len ))
		goto DISCARD;
	
	if(odp_unlikely( len > payload_len ))
		fstn_trimm_packet(pkt,payload_len+payload_off);

	if(odp_packet_has_tcp(pkt)){
		if(odp_unlikely(!fstn_tcp_input(pkt,thr)))
			goto ICMP_ERROR;
	} else if(odp_packet_has_udp(pkt)) {
		if(odp_unlikely(!fstn_udp_input(pkt,thr)))
			goto ICMP_ERROR;
	} else if(odp_packet_has_icmp(pkt)) {
		//fstn_icmp_input(pkt,thr);
	} else goto ICMP_ERROR;
	
	return;
	ICMP_ERROR:
	//fstn_icmp_error(thr, FNET_ICMP_UNREACHABLE, FNET_ICMP_UNREACHABLE_PROTOCOL,pkt);

	return;
	DISCARD:
	odp_packet_free(pkt);
}

/*
 * @brief sends an IPv6 Datagram
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function sends an IPv6 Datagram.
 */
void fstn_ipv6_output(odp_packet_t pkt, thr_s* thr){
	odph_ipv6hdr_t* hdr = odp_packet_l3_ptr(pkt,NULL);
	odph_ethhdr_t* eth_hdr;
	odph_ethaddr_t hwaddr;
	fstn_ipv6_t dst_ip = FSTN_IPV6_CAST(hdr->dst_addr);
	uint32_t size;

	/* Validate destination address. */
    /* RFC3513: The unspecified address must not be used as the destination address
     * of IPv6 packets or in IPv6 Routing Headers.*/ 
	if( fstn_ipv6_equals((const uint64_t*)hdr->src_addr,(const uint64_t*)in6addr_any.addr))
		goto DISCARD;
	
	hdr->ver_tc_flow = odp_cpu_to_be_32(0x60000000);
	hdr->payload_len = odp_cpu_to_be_16(odp_packet_len(pkt)-odp_packet_l4_offset(pkt));
	
	if(!hdr->hop_limit)
		hdr->hop_limit = thr->netif->ttl;
	
	if(odp_unlikely(!fstn_packet_add_l2(pkt,sizeof(odph_ethhdr_t))))
		goto DISCARD;

	eth_hdr = odp_packet_l2_ptr(pkt,NULL);
	eth_hdr->src = thr->netif->eth_address;
	
	if(  FNET_IP6_ADDR_IS_MULTICAST(dst_ip)  ){
		FNET_ETH_MULTICAST_IP6_TO_MAC(dst_ip,hwaddr.addr);
		eth_hdr->dst = hwaddr;
		fstn_eth_output(pkt,thr);
	} else if(odp_likely(fstn_eth_ipv6_target_or_queue(thr,dst_ip,&hwaddr,pkt) )) {
		eth_hdr->dst = hwaddr;
		fstn_eth_output(pkt,thr);
	} else {
		//fstn_arp_request(thr,dst_ip);
	}

	return;
	DISCARD:
	odp_packet_free(pkt);
}

