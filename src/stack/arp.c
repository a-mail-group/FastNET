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

/*
 * This file is derived from FNET as of version 3.0.0
 */

/*
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
		/* TODO: raise error! */
		goto DISCARD;
	}
	/*
	if(targer_prot_addr == ipv4_address) // It's for me.
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



