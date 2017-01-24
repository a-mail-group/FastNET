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
#include <net/nd6_cache.h>
#include <net/packet_output.h>

/* RFC-4861 */


netpp_retcode_t fastnet_nd6_nsol_input(odp_packet_t pkt,int source_is_unspecified){
	nd6_nsol_msg_t*  message;
	nd6_option_t     oh;
	odp_packet_t     sendchain;
	uint32_t         start,cur,end;
	uint8_t          src_mac[6];
	char             src_mac_len = 0;
	uint64_t         hwaddr;
	ipv6_addr_t      target_addr;
	odp_time_t       now;
	nif_t*           nif;
	nd6_nce_handle_t neighbor;
	nd6_nce_t*       neighptr;
	
	
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
	
	target_addr = message->target_addr;
	
	/* - Target Address is not a multicast address. */
	if(odp_unlikely(IP6_ADDR_IS_MULTICAST(target_addr))) return NETPP_DROP;
	
	
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
			if(odp_unlikely(odp_packet_copy_to_mem(pkt,cur+sizeof(oh),6,src_mac)))
				return NETPP_DROP;
			break;
		/*
		 * Consume others silently.
		 */
		}
		
		cur += oh.length<<3;
	}
	
	if(src_mac_len>0){
	
		/*
		 * - If the IP source address is the unspecified address, there is no
		 *    source link-layer address option in the message. (RFC-4861 7.1.1.)
		 */
		if(odp_unlikely(source_is_unspecified)) return NETPP_DROP;
		
		hwaddr = fastnet_mac_to_int(src_mac);
		
		now = odp_time_global();
		
		sendchain = ODP_PACKET_INVALID;
		
		/*
		 * RFC-4861 7.2.3.  Receipt of Neighbor Solicitations:
		 *
		 * If the Source Address is not the unspecified
		 * address and, on link layers that have addresses, the solicitation
		 * includes a Source Link-Layer Address option, then the recipient
		 * SHOULD create or update the Neighbor Cache entry for the IP Source
		 * Address of the solicitation.
		 */
		
		/*
		 * First lock the key.
		 */
		fastnet_nd6_nce_lock_key(nif,target_addr);
		
		/*
		 * First, check the neighbor cache, and create if necessary.
		 */
		neighbor = fastnet_nd6_nce_find_or_create(nif,target_addr,now);
		
		if(odp_unlikely( neighbor==ODP_BUFFER_INVALID ) ) {
			fastnet_nd6_nce_unlock_key(nif,target_addr);
			goto insert_or_update_done;
		}
		
		neighptr = odp_buffer_addr(neighbor);
		
		/*
		 * If an entry does not already exist, the
		 * node SHOULD create a new one and set its reachability state to STALE
		 * as specified in Section 7.3.3.
		 */
		if(neighptr->state == ND6_NC__PHANTOM_){
			neighptr->state        = ND6_NC_STALE;
			neighptr->state_tstamp = now;
			neighptr->hwaddr       = hwaddr;
			neighptr->is_router    = 0;
		} else
		
		switch(neighptr->state){
		case ND6_NC_STALE:
		case ND6_NC_REACHABLE:
		case ND6_NC_DELAY:
		case ND6_NC_PROBE:
			/*
			 * If an entry already exists, and the
			 * cached link-layer address differs from the one in the received Source
			 * Link-Layer option, the cached address should be replaced by the
			 * received address, and the entry's reachability state MUST be set to
			 * STALE.
			 */
			if(neighptr->hwaddr != hwaddr){
				neighptr->state        = ND6_NC_STALE;
				neighptr->state_tstamp = now;
				neighptr->hwaddr       = hwaddr;
			}
			break;
		case ND6_NC_INCOMPLETE:
			sendchain = neighptr->chain;
			neighptr->state        = ND6_NC_STALE;
			neighptr->state_tstamp = now;
			neighptr->hwaddr       = hwaddr;
			neighptr->chain        = ODP_PACKET_INVALID;
			break;
		}
		
		fastnet_nd6_nce_unlock(neighbor);
		fastnet_nd6_nce_put(neighbor);
		
		/* Send 'sendchain' packets. */
		fastnet_ip6_nd6_transmit(sendchain,nif,nif->hwaddr,hwaddr);
	}
insert_or_update_done:
	
	/* TODO: send Neighbor Advertisements. */
	
	return NETPP_DROP;
}


netpp_retcode_t fastnet_nd6_nadv_input(odp_packet_t pkt,int is_dest_multicast){
	nd6_nadv_msg_t*   message;
	nd6_option_t      oh;
	odp_packet_t      sendchain;
	uint32_t          start,cur,end;
	uint8_t           targ_mac[6];
	char              targ_mac_len = 0;
	uint64_t          hwaddr;
	nif_t*            nif;
	ipv6_addr_t       target_addr;
	uint8_t           msgflags;
	uint8_t           was_router;
	nd6_nce_handle_t  neighbor;
	nd6_nce_t*        neighptr;
	odp_time_t        now;
	
	
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
			if(odp_unlikely(odp_packet_copy_to_mem(pkt,cur+sizeof(oh),6,targ_mac)))
				return NETPP_DROP;
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
	
	msgflags = message->flags;
	
	hwaddr = fastnet_mac_to_int(targ_mac);
	
	sendchain = ODP_PACKET_INVALID;
	
	now = odp_time_global();
	
	/*
	 * First lock the key.
	 */
	fastnet_nd6_nce_lock_key(nif,target_addr);
	
	/*
	 * Then, check the neighbor cache.
	 */
	neighbor = fastnet_nd6_nce_find_only_valid(nif,target_addr);
	
	/*
	 * RFC-4861 7.2.5.  Receipt of Neighbor Advertisements
	 */
	if(neighbor == ODP_BUFFER_INVALID){
		/*
		 * There is no need to create an entry if none exists, since the
		 * recipient has apparently not initiated any communication with the
		 * target.
		 */
		fastnet_nd6_nce_unlock_key(nif,target_addr);
		return NETPP_DROP;
	}else{
		neighptr = odp_buffer_addr(neighbor);
	}
	
	/*
	 * State of IsRouter before update.
	 */
	was_router = neighptr->is_router;
	
	if(neighptr->state == ND6_NC_INCOMPLETE){
		/*
		 * If the target's Neighbor Cache entry is in the INCOMPLETE [...] the
		 * receiving node performs the following steps:
		 *
		 *  - It records the link-layer address in the Neighbor Cache entry.
		 */
		neighptr->hwaddr       = hwaddr;
		neighptr->state_tstamp = now;
		
		/*
		 *  - If the advertisement's Solicited flag is set, the state of the
		 *    entry is set to REACHABLE; otherwise, it is set to STALE.
		 */
		if(msgflags & ND6_NADV_SOLICITED)
			neighptr->state = ND6_NC_REACHABLE;
		else
			neighptr->state = ND6_NC_STALE;
		
		/*
		 *  - It sets the IsRouter flag in the cache entry based on the Router
		 *    flag in the received advertisement.
		 */
		if(msgflags & ND6_NADV_ROUTER)
			neighptr->is_router = 0xff;
		else
			neighptr->is_router = 0;
		
		/*
		 *  - It sends any packets queued for the neighbor awaiting address
		 *    resolution.
		 */
		sendchain              = neighptr->chain;
		neighptr->chain        = ODP_PACKET_INVALID;
	}else{
		/*
		 * If the target's Neighbor Cache entry is in any state other than
		 * INCOMPLETE when the advertisement is received, the following actions
		 * take place:
		 */
		
		if(msgflags & ND6_NADV_OVERRIDE){
			/*
			 * I. If the Override flag is clear and the supplied link-layer address
			 *    differs from that in the cache, then one of two actions takes
			 *    place:
			 *
			 *    a. If the state of the entry is REACHABLE, set it to STALE, but
			 *       do not update the entry in any other way.
			 *    b. Otherwise, the received advertisement should be ignored and
			 *       MUST NOT update the cache.
			 */
			if(neighptr->state == ND6_NC_REACHABLE){
				neighptr->state = ND6_NC_STALE;
			}
		}else{
			/*
			 * II. If the Override flag is set, or the supplied link-layer address
			 *     is the same as that in the cache, or no Target Link-Layer Address
			 *     option was supplied, the received advertisement MUST update the
			 *     Neighbor Cache entry as follows:
			 *
			 *     - The link-layer address in the Target Link-Layer Address option
			 *       MUST be inserted in the cache (if one is supplied and differs
			 *       from the already recorded address).
			 */
			neighptr->hwaddr = hwaddr;
			
			/*
			 *     - If the Solicited flag is set, the state of the entry MUST be
			 *       set to REACHABLE.  If the Solicited flag is zero and the link-
			 *       layer address was updated with a different address, the state
			 *       MUST be set to STALE.  Otherwise, the entry's state remains
			 *       unchanged.
			 */
			if(msgflags & ND6_NADV_SOLICITED)
				neighptr->state = ND6_NC_REACHABLE;
			else
				neighptr->state = ND6_NC_STALE;
			/*
			 *     - The IsRouter flag in the cache entry MUST be set based on the
			 *       Router flag in the received advertisement.
			 */
			if(msgflags & ND6_NADV_ROUTER)
				neighptr->is_router = 0xff;
			else
				neighptr->is_router = 0;
		}
	}
	
	/*
	 * If the IsRouter flag is set after Update, clear the WasRouter variable.
	 *
	 * After this, WasRouter is only TRUE if the IsRouter flag changed from TRUE to FALSE.
	 */
	if(neighptr->is_router) was_router = 0;
	
	/*
	 * In those cases
	 * where the IsRouter flag changes from TRUE to FALSE as a result
	 * of this update, the node MUST remove that router from the
	 * Default Router List and update the Destination Cache entries
	 * for all destinations using that neighbor as a router as
	 * specified in Section 7.3.3.
	 */
	if(was_router){
		fastnet_nd6_nce_rl_leave(neighbor);
	}
	
	fastnet_nd6_nce_unlock(neighbor);
	fastnet_nd6_nce_put(neighbor);
	
	/* Send 'sendchain' packets. */
	fastnet_ip6_nd6_transmit(sendchain,nif,nif->hwaddr,hwaddr);
	
	return NETPP_DROP;
}

netpp_retcode_t fastnet_nd6_radv_input(odp_packet_t pkt,ipv6_addr_t* ipaddr_p){
	nd6_radv_msg_t*     message;
	nif_t*              nif;
	uint32_t            start,cur,end;
	uint8_t             src_mac[6];
	char                src_mac_len = 0;
	uint64_t            hwaddr;
	uint32_t            mtu;
	uint8_t             has_mtu = 0;
	nd6_option_t        oh;
	nd6_option_prefix_t prefix;
	nd6_nce_handle_t    neighbor;
	nd6_nce_t*          neighptr;
	odp_time_t          now;
	uint16_t            router_lifetime;
	odp_packet_t        sendchain;
	
	nif = odp_packet_user_ptr(pkt);
	message = fastnet_safe_l4(pkt,sizeof(nd6_radv_msg_t));
	if(odp_unlikely(message==NULL)) return NETPP_DROP;
	
	start = odp_packet_l4_offset(pkt);
	end = odp_packet_len(pkt);
	
	/*
	 * RFC-4861 6.1.2.  Validation of Router Advertisement Messages
	 *
	 *  Checked in fastnet_icmpv6_input(): 
	 *   - IP Source Address is a link-local address.  Routers must use
	 *     their link-local address as the source for Router Advertisement
	 *     and Redirect messages so that hosts can uniquely identify
	 *     routers.
	 *   - The IP Hop Limit field has a value of 255, i.e., the packet
	 *     could not possibly have been forwarded by a router.
	 *   - ICMP Checksum is valid.
	 */
	
	/* - ICMP Code is 0. */
	if(odp_unlikely(message->icmp6.code != 0)) return NETPP_DROP;
	
	/* - ICMP length (derived from the IP length) is 16 or more octets. */
	if(odp_unlikely((end-start)<16)) return NETPP_DROP;
	
	cur = start + sizeof(nd6_nsol_msg_t);
	while(cur<end){
		if(odp_unlikely(odp_packet_copy_to_mem(pkt,cur,sizeof(oh),&oh)))
			return NETPP_DROP;
		
		/* - All included options have a length that is greater than zero. */
		if(odp_unlikely(oh.length == 0))
			return NETPP_DROP;
		
		switch(oh.type) {
		/*
		 * Source Link-Layer Address
		 */
		case ND6_OPTION_SLLA:
			src_mac_len = 6;
			if(odp_unlikely(odp_packet_copy_to_mem(pkt,cur+sizeof(oh),6,src_mac)))
				return NETPP_DROP;
			break;
		/*
		 * MTU
		 */
		case ND6_OPTION_MTU:
			has_mtu = 1;
			if(odp_unlikely(
				odp_packet_copy_to_mem(pkt,
					cur+ND6_OPTION_MTU_OFFSET,
					ND6_OPTION_MTU_LENGTH,
					&mtu))
			) return NETPP_DROP;
			mtu = odp_be_to_cpu_32(mtu);
			break;
		/*
		 * Consume others silently.
		 */
		}
		
		cur += oh.length<<3;
	}
	
	
	
	/*
	 * If the received Cur Hop Limit value is non-zero, the host SHOULD set
	 * its CurHopLimit variable to the received value.
	 */
	if(message->cur_hop_limit!=0){
		// TODO
	}
	
	/*
	 * If the received Reachable Time value is non-zero, the host SHOULD set
	 * its BaseReachableTime variable to the received value.
	 */
	if(message->reachable_time!=0){
		// TODO
	}
	
	/*
	 * The RetransTimer variable SHOULD be copied from the Retrans Timer
	 * field, if the received value is non-zero.
	 */
	if(message->retrans_timer!=0){
		// TODO
	}
	
	/*
	 * If the MTU option is present, hosts SHOULD copy the option's value
	 * into LinkMTU so long as the value is greater than or equal to the
	 * minimum link MTU [IPv6] and does not exceed the maximum LinkMTU value
	 * specified in the link-type-specific document (e.g., [IPv6-ETHER]).
	 */
	if(has_mtu){
		// TODO
	}
	
	
	/* ----------------------------------------------------------------- */
	
	/*
	 * NOTE THAT:
	 *   If a Neighbor Cache entry is created
	 *   for the router, its reachability state MUST be set to STALE as
	 *   specified in Section 7.3.3.  If a cache entry already exists and is
	 *   updated with a different link-layer address, the reachability state
	 *   MUST also be set to STALE.
	 */
	
	now = odp_time_global();
	
	sendchain = ODP_PACKET_INVALID;
	
	fastnet_nd6_nce_lock_key(nif,*ipaddr_p);
	
	
	/* Then, check the neighbor cache. */
	//neighbor = fastnet_nd6_nce_find(nif,*ipaddr_p);
	
	neighbor = ODP_BUFFER_INVALID;
	
	/*
	 * If the advertisement contains a Source Link-Layer Address
	 * option, the link-layer address SHOULD be recorded in the Neighbor
	 * Cache entry for the router (creating an entry if necessary) and the
	 * IsRouter flag in the Neighbor Cache entry MUST be set to TRUE.
	 */
	if(src_mac_len>0){
		hwaddr = fastnet_mac_to_int(src_mac);
		
		/* Find or create an Neighbor Cache Entry. */
		neighbor = fastnet_nd6_nce_find_or_create(nif,*ipaddr_p,now);
		if(odp_unlikely(neighbor==ODP_BUFFER_INVALID)) goto end_neighbor_cache_handling;
		neighptr = odp_buffer_addr(neighbor);
		neighptr->state = ND6_NC_STALE;
		neighptr->state_tstamp = now;
		neighptr->is_router    = 0xff;
		
		sendchain              = neighptr->chain;
		neighptr->chain        = ODP_PACKET_INVALID;
	}else{
		/*
		 * If no Source Link-Layer Address is included, but a corresponding Neighbor
		 * Cache entry exists, its IsRouter flag MUST be set to TRUE.
		 */
		neighbor = fastnet_nd6_nce_find(nif,*ipaddr_p);
		if(neighbor!=ODP_BUFFER_INVALID){
			neighptr = odp_buffer_addr(neighbor);
			neighptr               = odp_buffer_addr(neighbor);
			neighptr->state        = ND6_NC_STALE;
			neighptr->state_tstamp = now;
			neighptr->is_router    = 0xff;
		}
	}
	
	/* LEMMA: If an Entry exists, the variable 'neighbor' holds it. */
	
	router_lifetime = odp_be_to_cpu_16(message->router_lifetime);
	
	/*
	 * If the address is already present in the host's Default Router
	 * List and the received Router Lifetime value is zero, immediately
	 * time-out the entry as specified in Section 6.3.5.
	 */
	if(router_lifetime==0){
		if(neighbor!=ODP_BUFFER_INVALID){
			/* Remove it from the Default Router List. */
			fastnet_nd6_nce_rl_leave(neighbor);
			neighptr = odp_buffer_addr(neighbor);
			neighptr->router_lifetime = router_lifetime;
		}
	}
	/*
	 * If the address is not already present in the host's Default
	 * Router List, and the advertisement's Router Lifetime is non-
	 * zero, create a new entry in the list, and initialize its
	 * invalidation timer value from the advertisement's Router
	 * Lifetime field.
	 *
	 * If the address is already present in the host's Default Router
	 * List as a result of a previously received advertisement, reset
	 * its invalidation timer to the Router Lifetime value in the newly
	 * received advertisement.
	 */
	else{
		if(neighbor==ODP_BUFFER_INVALID)
			neighbor = fastnet_nd6_nce_find_or_create(nif,*ipaddr_p,now);
		
		if(odp_unlikely(neighbor==ODP_BUFFER_INVALID)) goto end_neighbor_cache_handling;
		
		neighptr                  = odp_buffer_addr(neighbor);
		neighptr->router_tstamp   = now;
		neighptr->router_lifetime = router_lifetime;
		
		/* Add it to the Default Router List.*/
		fastnet_nd6_nce_rl_enter(neighbor);
	}
	
	/*
	 * fastnet_nd6_nce_put() is "null-pointer-safe".
	 */
	fastnet_nd6_nce_put(neighbor);
	
end_neighbor_cache_handling:
	fastnet_nd6_nce_unlock_key(nif,*ipaddr_p);
	
	fastnet_ip6_nd6_transmit(sendchain,nif,nif->hwaddr,hwaddr);
	
	/* ----------------------------------------------------------------- */
	
	#if 0
	/* Loop through all Prefixes. */
	cur = start + sizeof(nd6_nsol_msg_t);
	while(cur<end){
		if(odp_unlikely(odp_packet_copy_to_mem(pkt,cur,sizeof(oh),&oh)))
			return NETPP_DROP;
		
		switch(oh.type) {
		case ND6_OPTION_PREFIX:
			if(odp_unlikely(
				odp_packet_copy_to_mem(pkt,
					cur+ND6_OPTION_PREFIX_OFFSET,
					sizeof(prefix),
					&prefix)
			)) break;
			// TODO ...
			break;
		}
		
		cur += oh.length<<3;
	}
	#endif
	
	return NETPP_DROP;
}

