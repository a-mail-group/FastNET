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

#include "arp.h"
#include "eth.h"
#include "fnet_arp.h"
#include "addrtable.h"
#include "generic.h"

/*
 * This file is derived from FNET as of version 3.0.0
 */

/**
 * @brief processes an arp input packet
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * ARP input function.
 */
void fstn_arp_input(odp_packet_t pkt, thr_s* thr){
	uint32_t size;
	uint32be_t sender_prot_addr,targer_prot_addr;
	odph_ethaddr_t  eth_address   = thr->netif->eth_address;
	uint32be_t      ipv4_address  = thr->netif->ipv4_address;

	fnet_arp_header_t *arp_hdr   = odp_packet_l3_ptr(pkt,&size);
	if( size < sizeof(arp_hdr)
		|| (odp_be_to_cpu_16(arp_hdr->hard_type) != FNET_ARP_HARD_TYPE)
		|| (arp_hdr->hard_size != FNET_ARP_HARD_SIZE)
		|| (odp_be_to_cpu_16(arp_hdr->prot_type) != ODPH_ETHTYPE_IPV4)
		|| (arp_hdr->prot_size != FNET_ARP_PROT_SIZE) )
		goto DISCARD;
	
	if(odp_be_to_cpu_16(arp_hdr->hard_type) != FNET_ARP_HARD_TYPE)
		goto DISCARD;
	
	sender_prot_addr = arp_hdr->sender_prot_addr;
	targer_prot_addr = arp_hdr->targer_prot_addr;
	if(sender_prot_addr == ipv4_address) {
		/* TODO: raise error/warning! Duplicate IP address! */
		goto DISCARD;
	}
	/*
	if(targer_prot_addr == ipv4_address) // It's for me. Who cares?
		;
	*/ 
	
	fstn_eth_ipv4_entry(thr,fstn_ipv4_cast(sender_prot_addr),arp_hdr->sender_hard_addr);
	
	if ((odp_be_to_cpu_16(arp_hdr->op) == FNET_ARP_OP_REQUEST) && (targer_prot_addr == ipv4_address))
	{
		odph_ethhdr_t *eth_hdr = odp_packet_l2_ptr(pkt,NULL);

		arp_hdr->op = odp_cpu_to_be_16(FNET_ARP_OP_REPLY); /* Opcode */

		arp_hdr->target_hard_addr = arp_hdr->sender_hard_addr;
		arp_hdr->sender_hard_addr = eth_address;

		arp_hdr->targer_prot_addr = arp_hdr->sender_prot_addr;
		arp_hdr->sender_prot_addr = ipv4_address;

		eth_hdr->dst = eth_hdr->src;
		eth_hdr->src = eth_address;

		fstn_eth_output(pkt,thr);
		return;
	}
	
	DISCARD:
	odp_packet_free(pkt);
}

/**
 * @brief Sends ARP request
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * Sends ARP request.
 */
void fstn_arp_request(thr_s* thr, uint32be_t ipaddr) {
    fnet_arp_header_t *arp_hdr;
	odph_ethhdr_t *eth_hdr;

	odp_packet_t pkt = fstn_alloc_packet(thr);
	if(odp_unlikely(pkt==ODP_PACKET_INVALID)) return;

	arp_hdr = odp_packet_push_tail(pkt,sizeof(fnet_arp_header_t));
	if(odp_unlikely( !arp_hdr ))
		goto DISCARD;

	eth_hdr = odp_packet_push_head(pkt,sizeof(odph_ethhdr_t));
	if(odp_unlikely( !eth_hdr ))
		goto DISCARD;

	eth_hdr->dst = fstn_eth_broadcast_addr;
	eth_hdr->src = thr->netif->eth_address;
	eth_hdr->type = odp_cpu_to_be_16(ODPH_ETHTYPE_ARP);
	
	arp_hdr->hard_type = odp_cpu_to_be_16(FNET_ARP_HARD_TYPE); /* The type of hardware address (=1 for
	                                                              Ethernet).*/
	arp_hdr->prot_type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);  /* The type of protocol address (=0x0800 for IP). */
	arp_hdr->hard_size = FNET_ARP_HARD_SIZE;                   /* The size in bytes of the
	                                                              hardware address (=6). */
	arp_hdr->prot_size = FNET_ARP_PROT_SIZE;                   /* The size in bytes of the
	                                                              protocol address (=4). */
	arp_hdr->op = odp_cpu_to_be_16(FNET_ARP_OP_REQUEST);       /* Opcode. */

	arp_hdr->target_hard_addr = fstn_eth_null_addr;
	arp_hdr->sender_hard_addr = thr->netif->eth_address;

	arp_hdr->targer_prot_addr = ipaddr;                   /* Protocol address of target of this packet.*/
	arp_hdr->sender_prot_addr = thr->netif->ipv4_address; /* Protocol address of sender of this packet.*/

	odp_packet_l2_offset_set(pkt,0);
	odp_packet_l3_offset_set(pkt,sizeof(odph_ethhdr_t));
	odp_packet_has_l2_set(pkt,1);
	odp_packet_has_l3_set(pkt,1);
	odp_packet_has_eth_set(pkt,1);
	odp_packet_has_arp_set(pkt,1);

	fstn_eth_output(pkt,thr);

	return;
	DISCARD:
	odp_packet_free(pkt);
}



