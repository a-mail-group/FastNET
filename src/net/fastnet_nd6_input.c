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
#include <net/nd6.h>
#include <net/header/nd6.h>
#include <net/safe_packet.h>
#include <net/header/ip6defs.h>
#include <net/mac_addr_ldst.h>
#include <net/ipv6_mac_cache.h>

/* RFC-4861 */


netpp_retcode_t fastnet_nd6_nsol_input(odp_packet_t pkt,int source_is_unspecified){
	nd6_nsol_msg_t* message;
	nd6_option_t    oh;
	odp_packet_t    sendchain;
	uint32_t        start,cur,end;
	uint8_t         src_mac[6];
	char            src_mac_len = 0;
	uint64_t        hwaddr;
	nif_t*          nif;
	
	nif = odp_packet_user_ptr(pkt);
	message = fastnet_safe_l4(pkt,sizeof(nd6_nsol_msg_t));
	if(odp_unlikely(message==NULL)) return NETPP_DROP;
	
	start = odp_packet_l4_offset(pkt);
	end = odp_packet_len(pkt);
	
	/*
	 * RFC-4861 7.1.1.  Validation of Neighbor Solicitations
	 *
	 *  Checked in fastnet_icmpv6_input(): 
	 *    - The IP Hop Limit field has a value of 255, i.e., the packet
	 *      could not possibly have been forwarded by a router.
	 *    - ICMP Checksum is valid.
	 *    - If the IP source address is the unspecified address, the IP
	 *      destination address is a solicited-node multicast address.
	 */
	
	
	/* - ICMP Code is 0. */
	if(odp_unlikely(message->icmp6.code != 0)) return NETPP_DROP;
	
	/* - ICMP length (derived from the IP length) is 24 or more octets. */
	if(odp_unlikely((end-start)<24)) return NETPP_DROP;
	
	/* - Target Address is not a multicast address. */
	if(odp_unlikely(IP6_ADDR_IS_MULTICAST(message->target_addr))) return NETPP_DROP;
	
	
	cur = start + sizeof(nd6_nsol_msg_t);
	while(cur<end){
		if(odp_unlikely(odp_packet_copy_to_mem(pkt,cur,sizeof(oh),&oh)))
			return NETPP_DROP;
		
		/* All included options have a length that is greater than zero. */
		if(odp_unlikely(oh.length == 0))
			return NETPP_DROP;
		
		switch(oh.type) {
		/*
		 * Source LLA is interesting for us.
		 */
		case ND6_OPTION_SLLA:
			src_mac_len = 6;
			if(odp_unlikely(odp_packet_copy_to_mem(pkt,cur,6,src_mac))) return NETPP_DROP;
			break;
		/*
		 * Consume others silently.
		 */
		}
		
		cur += oh.length<<3;
	}
	
	/*
	 * RFC-4861 7.2.3.  Receipt of Neighbor Solicitations
	 *
	 * If the Source Address is not the unspecified
	 * address and, on link layers that have addresses, the solicitation
	 * includes a Source Link-Layer Address option, then the recipient
	 * SHOULD create or update the Neighbor Cache entry for the IP Source
	 * Address of the solicitation.   If an entry does not already exist, the
	 * node SHOULD create a new one and set its reachability state to STALE
	 * as specified in Section 7.3.3.  If an entry already exists, and the
	 * cached link-layer address differs from the one in the received Source
	 * Link-Layer option, the cached address should be replaced by the
	 * received address, and the entry's reachability state MUST be set to
	 * STALE.
	 *
	 */
	if(src_mac_len>0){
	
		/*
		 * - If the IP source address is the unspecified address, there is no
		 *    source link-layer address option in the message. (RFC-4861 7.1.1.)
		 */
		if(odp_unlikely(source_is_unspecified)) return NETPP_DROP;
	
		hwaddr = fastnet_mac_to_int(src_mac);
		sendchain = fastnet_ipv6_mac_nsol(nif,message->target_addr,hwaddr);
		
		/* TODO: send sendchain. */
	}
	
	/* TODO: send Neighbor Advertisements. */
	
	return NETPP_DROP;
}


netpp_retcode_t fastnet_nd6_nadv_input(odp_packet_t pkt,int is_dest_multicast){
	nd6_nadv_msg_t* message;
	nd6_option_t    oh;
	odp_packet_t    sendchain;
	uint32_t        start,cur,end;
	uint8_t         targ_mac[6];
	char            targ_mac_len = 0;
	uint64_t        hwaddr;
	nif_t*          nif;
	ipv6_addr_t     target_addr;
	int             callflags;
	uint8_t         msgflags;
	
	nif = odp_packet_user_ptr(pkt);
	message = fastnet_safe_l4(pkt,sizeof(nd6_nadv_msg_t));
	if(odp_unlikely(message==NULL)) return NETPP_DROP;
	
	start = odp_packet_l4_offset(pkt);
	end = odp_packet_len(pkt);
	
	/*
	 * RFC-4861 7.1.2.  Validation of Neighbor Advertisements
	 *
	 *  Checked in fastnet_icmpv6_input(): 
	 *    - The IP Hop Limit field has a value of 255, i.e., the packet
	 *      could not possibly have been forwarded by a router.
	 *    - ICMP Checksum is valid.
	 */
	 
	 /* - ICMP Code is 0. */
	if(odp_unlikely(message->icmp6.code != 0)) return NETPP_DROP;
	
	/* - ICMP length (derived from the IP length) is 24 or more octets. */
	if(odp_unlikely((end-start)<24)) return NETPP_DROP;
	
	target_addr = message->target_addr;
	
	/* - Target Address is not a multicast address. */
	if(odp_unlikely(IP6_ADDR_IS_MULTICAST(target_addr))) return NETPP_DROP;
	
	/*
	 * - If the IP Destination Address is a multicast address the
	 *   Solicited flag is zero.
	 */
	if(is_dest_multicast) {
		if(odp_unlikely(message->flags & ND6_NADV_SOLICITED)) return NETPP_DROP;
	}
	
	cur = start + sizeof(nd6_nsol_msg_t);
	while(cur<end){
		if(odp_unlikely(odp_packet_copy_to_mem(pkt,cur,sizeof(oh),&oh)))
			return NETPP_DROP;
		
		/* All included options have a length that is greater than zero. */
		if(odp_unlikely(oh.length == 0))
			return NETPP_DROP;
		
		switch(oh.type) {
		/*
		 * Target LLA is interesting for us.
		 */
		case ND6_OPTION_TLLA:
			targ_mac_len = 6;
			if(odp_unlikely(odp_packet_copy_to_mem(pkt,cur,6,targ_mac))) return NETPP_DROP;
			break;
		/*
		 * Consume others silently.
		 */
		}
		
		cur += oh.length<<3;
	}
	
	/*
	 * If the target's Neighbor Cache entry is in the INCOMPLETE state when
	 * the advertisement is received, one of two things happens.  If the
	 * link layer has addresses and no Target Link-Layer Address option is
	 * included, the receiving node SHOULD silently discard the received
	 * advertisement.
	 */
	if(odp_unlikely(targ_mac_len==0)) return NETPP_DROP;
	
	callflags = 0;
	msgflags = message->flags;
	if(msgflags & ND6_NADV_ROUTER)    callflags |= I6MC_NADV_ROUTER;
	if(msgflags & ND6_NADV_SOLICITED) callflags |= I6MC_NADV_SOLICITED;
	if(msgflags & ND6_NADV_OVERRIDE)  callflags |= I6MC_NADV_OVERRIDE;
	
	hwaddr = fastnet_mac_to_int(targ_mac);
	
	sendchain = fastnet_ipv6_mac_nadv(nif,target_addr,hwaddr,callflags);
	
	/* TODO: send sendchain. */
	
	return NETPP_DROP;
}

