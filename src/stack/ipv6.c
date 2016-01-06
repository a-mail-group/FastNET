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
#include "arp.h"
#include "tcp.h"
#include "udp.h"
#include <odp/helper/ip.h>
#include "ip_addr_ext.h"
#include "addrtable.h"

/*
 * This file is derived from FNET as of version 3.0.0
 */


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
}

