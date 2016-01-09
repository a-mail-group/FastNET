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
#include "icmp6.h"
#include "nd6.h"
#include "ip_addr_ext.h"
#include "prot.h"
#include <odp/helper/icmp.h>
#include <odp/helper/ip.h>
#include "generic.h"

/*
 * This file is derived from FNET as of version 3.0.0
 */

static inline void fstn_swap_ip6_addr(odp_packet_t pkt, thr_s* thr) {
	odph_ipv6hdr_t* hdr = odp_packet_l3_ptr(pkt,NULL);
	fstn_ipv6_t temp = FSTN_IPV6_CAST(hdr->dst_addr);
	FSTN_IPV6_CAST(hdr->dst_addr) = FSTN_IPV6_CAST(hdr->src_addr);
	FSTN_IPV6_CAST(hdr->src_addr) = temp;
	hdr->hop_limit                = 0;
}

typedef struct ODP_PACKED {
	odph_icmphdr_t header;
	odph_ipv6hdr_t iph;
	uint16be_t src_port;
	uint16be_t dst_port;
} fstn_icmp_err_t;

/*
 * NAME: fnet_icmp_notify_protocol
 *
 * DESCRIPTION: Upper protocol notification..
 */
static void fstn_icmp6_notify_protocol(thr_s *thr, fnotify_t prot_cmd, odp_packet_t pkt)
{
	uint32_t size;
	fstn_icmp_err_t         *hdr_err = odp_packet_l4_ptr(pkt,&size);
	if(odp_unlikely( size<sizeof(fstn_icmp_err_t) ))
		goto DISCARD;
	odph_ipv6hdr_t          *ip_header = &hdr_err->iph;
	fstn_control_param_t ctrl;

	ctrl.src_port = hdr_err->src_port;
	ctrl.dst_port = hdr_err->dst_port;
	FSTN_IPV6_CAST(ctrl.src_ip.ipv6) = FSTN_IPV6_CAST(ip_header->src_addr);
	FSTN_IPV6_CAST(ctrl.dst_ip.ipv6) = FSTN_IPV6_CAST(ip_header->dst_addr);
	ctrl.protocol = ip_header->next_hdr;
	ctrl.prot_cmd = prot_cmd;
	ctrl.v6 = 1; /* 1 = IPv6 */
	fstn_protoc_notify(thr, &ctrl, pkt);

	return;
DISCARD:
     odp_packet_free(pkt);
}

/*
 * @brief processes an icmp packet
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function processes an icmp packet.
 */
void fstn_icmp6_input(odp_packet_t pkt, thr_s* thr){
	odph_icmphdr_t      *hdr;
    fnotify_t           prot_cmd;
	fstn_ipv6_t         dest_ip;
	uint32_t            size;
	
	hdr = odp_packet_l4_ptr(pkt,&size);
	if(odp_unlikely( size<ODPH_ICMPHDR_LEN ))
		goto DISCARD;
	
	dest_ip = FSTN_IPV6_CAST(((odph_ipv6hdr_t*)odp_packet_l4_ptr(pkt,NULL))->dst_addr);

    	switch (hdr->type) 
    	{
            /**************************
             * Neighbor Solicitation.
             **************************/
            case FNET_ICMP6_TYPE_NEIGHBOR_SOLICITATION:
                fstn_nd6_neighbor_solicitation_receive(pkt,thr);
                break;
            /**************************
             * Neighbor Advertisemnt.
             **************************/            
            case FNET_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT:
                fstn_nd6_neighbor_advertisement_receive(pkt,thr);
                break;                
            /**************************
             * Router Advertisemnt.
             **************************/
            case FNET_ICMP6_TYPE_ROUTER_ADVERTISEMENT:
                fstn_nd6_router_advertisement_receive(pkt,thr);
                break; 
            /**************************
             * Router Advertisemnt.
             **************************/
            case FNET_ICMP6_TYPE_REDIRECT:
                fstn_nd6_redirect_receive(pkt,thr);
                break;
        #if 0 //FNET_CFG_MLD 
            /**************************
             * Multicast Listener Query.
             **************************/
            case FNET_ICMP6_TYPE_MULTICAST_LISTENER_QUERY:
                fnet_mld_query_receive(netif, src_ip, dest_ip, nb, ip6_nb);
                break;
        #endif                                
            /**************************
             * Echo Request.
             * RFC4443 4.1: Every node MUST implement an ICMPv6 Echo responder function that
             * receives Echo Requests and originates corresponding Echo Replies.             
             **************************/
            case FNET_ICMP6_TYPE_ECHO_REQ:
                hdr->type = FNET_ICMP6_TYPE_ECHO_REPLY;
                
                /* RFC4443: the source address of the reply MUST be a unicast 
                 * address belonging to the interface on which 
                 * the Echo Request message was received.*/
                if(FNET_IP6_ADDR_IS_MULTICAST(dest_ip))
                {
                     //dest_ip = FNET_NULL;
                     FSTN_IPV6_CAST(((odph_ipv6hdr_t*)odp_packet_l4_ptr(pkt,NULL))->dst_addr)
                        = FSTN_IPV6_CAST(thr->netif->ipv6_address);
                }
                
                fstn_swap_ip6_addr(pkt, thr);
                fstn_icmp6_output(pkt, thr);
                break;   
        #if 0// FNET_CFG_IP6_PMTU_DISCOVERY 
           /**************************
            * Packet Too Big Message.
            **************************/
            case FNET_ICMP6_TYPE_PACKET_TOOBIG:     
                if(netif->pmtu) /* If PMTU is enabled for the interface.*/
                {
                    fnet_uint32_t           pmtu;
                    fnet_icmp6_err_header_t *icmp6_err = (fnet_icmp6_err_header_t *)nb->data_ptr;
                    
                    /* The header must reside in contiguous area of memory. */
                    if(fnet_netbuf_pullup(&nb, sizeof(fnet_icmp6_err_header_t)) == FNET_ERR) 
                    {
                        goto DISCARD;
                    }
                    
                    /* RFC 1981.Upon receipt of such a
                     * message, the source node reduces its assumed PMTU for the path based
                     * on the MTU of the constricting hop as reported in the Packet Too Big
                     * message.*/
                    pmtu = fnet_ntohl(icmp6_err->data); 

                    /* A node MUST NOT increase its estimate of the Path MTU in response to
                     * the contents of a Packet Too Big message. */
                    if(netif->pmtu > pmtu)        
                    {
                        fnet_netif_set_pmtu(netif, pmtu);
                    }                
                }

                goto DISCARD;
        #endif   
           /**************************
            * Destination Unreachable. 
            **************************/
            case FNET_ICMP6_TYPE_DEST_UNREACH:
                switch(hdr->code)
                {
                    case FNET_ICMP6_CODE_DU_NO_ROUTE:           /* No route to destination. */
                    case FNET_ICMP6_CODE_DU_BEYOND_SCOPE:       /* Beyond scope of source address.*/
                        prot_cmd = FNET_PROT_NOTIFY_UNREACH_NET;
                        break;
                    case FNET_ICMP6_CODE_DU_ADMIN_PROHIBITED:   /* Communication with destination administratively prohibited. */
                    case FNET_ICMP6_CODE_DU_ADDR_UNREACH:       /* Address unreachable.*/
                        prot_cmd = FNET_PROT_NOTIFY_UNREACH_HOST;
                        break;
                    case FNET_ICMP6_CODE_DU_PORT_UNREACH:       /* Port unreachable.*/
                        prot_cmd = FNET_PROT_NOTIFY_UNREACH_PORT;
                        break;
                    default:
                        goto DISCARD;
                }

                fstn_icmp6_notify_protocol(thr, prot_cmd, pkt);
                break;
            default:
                goto DISCARD;
        }   

	return;
	DISCARD:
	odp_packet_free(pkt);
}

/*
 * @brief sends an icmp packet
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function sends an icmp packet.
 */
void fstn_icmp6_output(odp_packet_t pkt, thr_s* thr){
	uint32_t size;
	if(odp_unlikely(!fstn_packet_cut_l2(pkt)))
		goto DISCARD;

	odph_icmphdr_t *hdr = odp_packet_l4_ptr(pkt,&size);
	hdr->chksum = 0u;
	hdr->chksum = odp_chksum(hdr, size);

	((odph_ipv6hdr_t*)odp_packet_l3_ptr(pkt,NULL))->next_hdr = ODPH_IPPROTO_ICMP;

	fstn_ipv6_output(pkt,thr);

	return;
	DISCARD:
	odp_packet_free(pkt);
}

/*
 * @brief sends an icmp error message
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function sends an icmp error message.
 */
void fstn_icmp6_error(thr_s* thr, uint8_t type,uint8_t code,uint32_t param,odp_packet_t cause){
	uint32_t size_errorpkt;
	uint32_t size;
	uint8_t ctype;

	fstn_ipv6_t src,dst;
	odph_ipv6hdr_t *iph  = odp_packet_l3_ptr(cause,&size);
	size_errorpkt = sizeof(odph_ipv6hdr_t)+8;

	src = FSTN_IPV6_CAST(iph->src_addr);
	dst = FSTN_IPV6_CAST(iph->dst_addr);

	/*******************************************************************
	 * RFC 4443:
	 * (e) An ICMPv6 error message MUST NOT be originated as a result of
	 * receiving the following:
	 *******************************************************************/
	/* (e.1) An ICMPv6 error message. */ 
	/* (e.2) An ICMPv6 REDIRECT message [IPv6-DISC].*/
	if(odp_packet_has_icmp(cause)){
		ctype = ((odph_icmphdr_t*)odp_packet_l4_ptr(cause,NULL))->type;
		if( odp_unlikely(FNET_ICMP6_TYPE_IS_ERROR(ctype) || ctype == FNET_ICMP6_TYPE_REDIRECT) )
			goto DISCARD;
	}


	/*
	 * (e.3) A packet destined to an IPv6 multicast address. (There are
	 * two exceptions to this rule: (1) the Packet Too Big Message
	 * (Section 3.2) to allow Path MTU discovery to work for IPv6
	 * multicast, and (2) the Parameter Problem Message, Code 2
	 * (Section 3.4) reporting an unrecognized IPv6 option (see
	 * Section 4.2 of [IPv6]) that has the Option Type highestorder
	 * two bits set to 10).
	 * (e.4) A packet sent as a link-layer multicast (the exceptions
	 * from e.3 apply to this case, too).     
	 */
	if(FNET_IP6_ADDR_IS_MULTICAST(dst)
		&& (!( (type == FNET_ICMP6_TYPE_PACKET_TOOBIG) 
			|| ((type == FNET_ICMP6_TYPE_PARAM_PROB) && (code == FNET_ICMP6_CODE_PP_OPTION)))) )
				goto DISCARD;

	if(FNET_IP6_ADDR_IS_MULTICAST(dst))
		dst = FSTN_IPV6_CAST(thr->netif->ipv6_address);

	/*
	 * (e.5) A packet sent as a link-layer broadcast (the exceptions
	 *  from e.3 apply to this case, too). TBD
	 */  

	/*
	 * (e.6) A packet whose source address does not uniquely identify a
	 * single node -- e.g., the IPv6 Unspecified Address, an IPv6
	 * multicast address, or an address known by the ICMP message
	 * originator to be an IPv6 anycast address.
	 */
	if(FNET_IP6_ADDR_IS_MULTICAST(src) || FSTN_IPV6_EQUALS(src,in6addr_any) )
		goto DISCARD;

	odp_packet_t pkt = fstn_alloc_packet(thr);
	if(odp_unlikely(pkt==ODP_PACKET_INVALID))
		goto DISCARD;

	if(odp_likely(size>size_errorpkt))
		size = size_errorpkt;

	odp_packet_push_tail(pkt,size);
	odp_packet_copydata_in(pkt,0,size,iph);


	odph_icmphdr_t *icmp = odp_packet_push_head(pkt,sizeof(odph_icmphdr_t));
	icmp->un.gateway = 0;
	icmp->type = type;
	icmp->code = code;

	odph_ipv6hdr_t *niph = odp_packet_push_head(pkt,sizeof(odph_ipv6hdr_t));
	niph->hop_limit = 0;
	FSTN_IPV6_CAST(niph->dst_addr) = FSTN_IPV6_CAST(iph->src_addr);
	FSTN_IPV6_CAST(niph->src_addr) = FSTN_IPV6_CAST(iph->dst_addr);

	odp_packet_has_l3_set(pkt,1);
	odp_packet_has_ipv6_set(pkt,1);
	odp_packet_l3_offset_set(pkt,0);
	odp_packet_l4_offset_set(pkt,sizeof(odph_ipv6hdr_t));

	fstn_icmp6_output(pkt,thr);

	DISCARD:
	odp_packet_free(cause);
}



