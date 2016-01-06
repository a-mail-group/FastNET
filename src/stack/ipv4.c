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

#include "ipv4.h"
#include "icmp.h"
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

/*
 * @brief processes an IPv4 Datagram
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function processes an IPv4 Datagram.
 */
void fstn_ipv4_input(odp_packet_t pkt, thr_s* thr){
	fstn_ipv4_t src,dst;
	uint32_t len,ip_len,ip_off;
	odph_ipv4hdr_t* hdr = odp_packet_l3_ptr(pkt,&len);
	odph_ethhdr_t* eth_hdr = odp_packet_l2_ptr(pkt,NULL);

	if(odp_unlikely( len < ODPH_IPV4HDR_LEN ))
		goto DISCARD;

	src.as_odp = hdr->src_addr;
	dst.as_odp = hdr->dst_addr;
	
	/* Is it for me? */
	if(odp_unlikely(!(
		(dst.as_odp == thr->netif->ipv4_address) ||
		(dst.as_odp == thr->netif->ipv4_netbroadcast) ||
		(FNET_IP4_ADDR_IS_MULTICAST(dst)) ||
		(dst.as_odp == FSTN_IP4_BROADCAST)
		)))
		goto DISCARD;
	
	ip_off = odp_packet_l3_offset(pkt);
	len = odp_packet_len(pkt)-ip_off;
	
	ip_len = odp_be_to_cpu_16(hdr->tot_len);

	if(odp_unlikely( len < ip_len ))
		goto DISCARD;
	
	if(odp_unlikely( len > ip_len ))
		fstn_trimm_packet(pkt,ip_len+ip_off);

	if(odp_likely(
		(dst.as_odp != thr->netif->ipv4_netbroadcast) &&
		(dst.as_odp != FSTN_IP4_BROADCAST) &&
		(!FNET_IP4_ADDR_IS_MULTICAST(dst))    ))
			fstn_eth_ipv4_entry(thr,src,eth_hdr->src);

	/* Reassembly.*/
	if(odp_unlikely(ODPH_IPV4HDR_IS_FRAGMENT(
			odp_be_to_cpu_16(hdr->frag_offset))))
			/* the MF bit or fragment offset is nonzero.*/
	{ //TODO: fragmentation
    #if 0
		// FNET_CFG_IP4_FRAGMENTATION
		if((nb = fnet_ip_reassembly(&nb)) == 0)
		{
			return;
		}
		hdr = (fnet_ip_header_t *)nb->data_ptr;
		header_length = (fnet_size_t)FNET_IP_HEADER_GET_HEADER_LENGTH(hdr) << 2;
    #else
		goto DISCARD;
    #endif
	}

	if(odp_packet_has_tcp(pkt)){
		if(odp_unlikely(!fstn_tcp_input(pkt,thr)))
			goto ICMP_ERROR;
	} else if(odp_packet_has_udp(pkt)) {
		if(odp_unlikely(!fstn_udp_input(pkt,thr)))
			goto ICMP_ERROR;
	} else if(odp_packet_has_icmp(pkt)) {
		fstn_icmp_input(pkt,thr);
	} else goto ICMP_ERROR;
	
	return;
	ICMP_ERROR:
	fstn_icmp_error(thr, FNET_ICMP_UNREACHABLE, FNET_ICMP_UNREACHABLE_PROTOCOL,pkt);

	return;
	DISCARD:
	odp_packet_free(pkt);
}

/*
 * @brief sends an IPv4 Datagram
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function sends an IPv4 Datagram.
 */
void fstn_ipv4_output(odp_packet_t pkt, thr_s* thr){
	odph_ipv4hdr_t* hdr = odp_packet_l3_ptr(pkt,NULL);
	odph_ethhdr_t* eth_hdr;
	odph_ethaddr_t hwaddr;
	uint32be_t dst_ip = hdr->dst_addr;

	if(hdr->src_addr == 0) /* 0 = inaddr_any */
		hdr->src_addr = thr->netif->ipv4_address;
	
	odph_ipv4_csum_update(pkt);
	
	if(odp_unlikely(!fstn_packet_add_l2(pkt,sizeof(odph_ethhdr_t),0)))
		goto DISCARD;

	eth_hdr = odp_packet_l2_ptr(pkt,NULL);
	eth_hdr->src = thr->netif->eth_address;
	
	if(odp_likely(fstn_eth_ipv4_target_or_queue(thr,fstn_ipv4_cast(dst_ip),&hwaddr,pkt) )){
		eth_hdr->dst = hwaddr;
		fstn_eth_output(pkt,thr);
	}else{
		fstn_arp_request(thr,dst_ip);
	}

	return;
	DISCARD:
	odp_packet_free(pkt);
}




