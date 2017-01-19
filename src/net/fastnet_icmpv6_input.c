/*
 *   Copyright 2017 Simon Schmidt
 *   Copyright 2011-2016 by Andrey Butok. FNET Community.
 *   Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
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
#include <net/packet_input.h>
#include <net/packet_output.h>
#include <net/header/icmp6.h>
#include <net/header/ip6hdr.h>
#include <net/header/ip6defs.h>
#include <net/checksum.h>
#include <net/header/layer4.h>
#include <net/_config.h>
#include <net/defaults.h>
#include <net/safe_packet.h>

typedef struct{
	ipv6_addr_t src,dst;
} ip6_pair_t;

/* XXX: put this elsewhere.*/
typedef enum
{
    FNET_PROT_NOTIFY_QUENCH,           /* Some one said to slow down.*/
    FNET_PROT_NOTIFY_MSGSIZE,          /* Message size forced drop.*/
    FNET_PROT_NOTIFY_UNREACH_HOST,     /* No route to host.*/
    FNET_PROT_NOTIFY_UNREACH_PROTOCOL, /* Dst says bad protocol.*/
    FNET_PROT_NOTIFY_UNREACH_PORT,     /* Bad port #.*/
    FNET_PROT_NOTIFY_UNREACH_SRCFAIL,  /* Source route failed.*/
    FNET_PROT_NOTIFY_UNREACH_NET,      /* No route to network.*/
    FNET_PROT_NOTIFY_TIMXCEED_INTRANS, /* Packet time-to-live expired in transit.*/
    FNET_PROT_NOTIFY_TIMXCEED_REASS,   /* Reassembly time-to-leave expired.*/
    FNET_PROT_NOTIFY_PARAMPROB         /* Header incorrect.*/
} fnet_prot_notify_t;

static inline
struct ipv6_nif_struct* getIpv6(odp_packet_t pkt, nif_t** pnif){
	nif_t* nif;
	struct ipv6_nif_struct* ipv6;
	*pnif = nif = odp_packet_user_ptr(pkt);
	return odp_likely(nif != NULL) ? nif->ipv6 : NULL;
}



static inline
netpp_retcode_t get_ip6_pair(ip6_pair_t* pair,odp_packet_t pkt,struct ipv6_nif_struct* ipv6){
	fnet_ip6_header_t *ip6;
	
	ip6 = fastnet_safe_l3(pkt,sizeof(fnet_ip6_header_t));
	if(odp_unlikely(!ip6)) return NETPP_DROP;
	
	pair->src = ip6->source_addr;
	pair->dst = ip6->destination_addr;
	
	return NETPP_CONTINUE;
}

static inline
void add_response_header(ip6_pair_t* pair,odp_packet_t pkt,uint32_t pktlen,uint32_t offset){
	fnet_ip6_header_t* ip;
	
	if(offset >= sizeof(fnet_ip6_header_t)){
		odp_packet_l3_offset_set(pkt,offset-sizeof(fnet_ip6_header_t));
		ip = odp_packet_l3_ptr(pkt,NULL);
	}else{
		ip = odp_packet_push_head(pkt,sizeof(fnet_ip6_header_t)-offset);
		odp_packet_l3_offset_set(pkt,0);
		odp_packet_l4_offset_set(pkt,sizeof(fnet_ip6_header_t));
	}
	
	/*
	 * The IP-version is 6, the Traffic Class is 0x00 and the
	 * Flow Label is 0x00000 (will be set by the IPv6 stack).
	 */
	ip->version_tclass_flowl  = odp_cpu_to_be_32(0x60000000); // tclass = 0
	ip->length                = odp_cpu_to_be_16(pktlen);
	ip->next_header           = IP_PROTOCOL_ICMP6;
	ip->hop_limit             = DATAGRAM_TTL;
	/*
	 * In the response header, Source and Destination addresses are swapped.
	 */
	ip->source_addr            = pair->dst;
	ip->destination_addr        = pair->src;
}

netpp_retcode_t fastnet_icmpv6_input(odp_packet_t pkt){
	fnet_prot_notify_t       prot_cmd;
	ip6_pair_t               pair;
	netpp_retcode_t          ret;
	struct ipv6_nif_struct*  ipv6;
	nif_t*                   nif;
	fnet_icmp6_header_t*     hdr;
	uint32_t                 pktlen,pktoff;
	
	ipv6 = getIpv6(pkt,&nif);
	
	ret = get_ip6_pair(&pair,pkt,ipv6);
	if(odp_unlikely(ret != NETPP_CONTINUE)) return ret;
	
	hdr = fastnet_safe_l4(pkt,sizeof(fnet_icmp6_header_t));
	if(odp_unlikely(!hdr)) return NETPP_DROP;
	
	pktoff = odp_packet_l4_offset(pkt);
	pktlen = odp_packet_len(pkt);
	pktlen -= pktoff;
	
	/*
	 * Checksum test.
	 */
	if(odp_unlikely( fastnet_ip6_checksum(pkt,pair.src,pair.dst,IP_PROTOCOL_ICMP6) != 0 )) return NETPP_DROP;
	
	
	switch (hdr->type){
	/**************************
	 * Neighbor Solicitation.
	 **************************/
	case FNET_ICMP6_TYPE_NEIGHBOR_SOLICITATION:
		//netnd6_neighbor_solicitation_receive(nif,pkt,&src_ip,&dest_ip);
		break;
	/**************************
	 * Neighbor Advertisemnt.
	 **************************/
	case FNET_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT:
		//netnd6_neighbor_advertisement_receive(nif,pkt,&src_ip,&dest_ip);
		break;
	/**************************
	 * Router Advertisemnt.
	 **************************/
	case FNET_ICMP6_TYPE_ROUTER_ADVERTISEMENT:
		//netnd6_router_advertisement_receive(nif,pkt,&src_ip,&dest_ip);
		break;
	/**************************
	 * Router Advertisemnt.
	 **************************/
	case FNET_ICMP6_TYPE_REDIRECT:
		//netnd6_redirect_receive(nif,pkt,&src_ip,&dest_ip);
		break;
	/**************************
	 * Multicast Listener Query.
	 **************************/
	case FNET_ICMP6_TYPE_MULTICAST_LISTENER_QUERY:
		//fnet_mld_query_receive(netif, src_ip, dest_ip, nb, ip6_nb);
		break;
	/**************************
	 * Echo Request.
	 * RFC4443 4.1: Every node MUST implement an ICMPv6 Echo responder function that
	 * receives Echo Requests and originates corresponding Echo Replies.
	 **************************/
	case FNET_ICMP6_TYPE_ECHO_REQ:
		/*
		 * RFC4443: the source address of the reply MUST be a unicast
		 * address belonging to the interface on which
		 * the Echo Request message was received.
		 */
		if(IP6_ADDR_IS_MULTICAST(pair.dst)) return NETPP_DROP; /* TODO: find corresponding dest_ip to src_ip */
		
		hdr->type = FNET_ICMP6_TYPE_ECHO_REPLY;
		hdr->checksum = 0;
		hdr->checksum = fastnet_ip6_checksum(pkt,pair.dst,pair.src,IP_PROTOCOL_ICMP6);
		
		add_response_header(&pair,pkt,pktlen,pktoff);
		
		// TODO: send IPv6
		//neticmp6_output(nif,pkt,dst_addr,src_addr,0);
                break;
	/**************************
	 * Packet Too Big Message.
	 **************************/
	case FNET_ICMP6_TYPE_PACKET_TOOBIG:
	#if 0
		if(nif->ipv6->pmtu_on) /* If PMTU is enabled for the interface.*/
		{
			
			
			/* The header must reside in contiguous area of memory. */
			if( netpkt_pullup(pkt,sizeof(fnet_icmp6_err_header_t)) ) goto DROP;
			
			icmp6_err = netpkt_data(pkt);
			
			/* RFC 1981.Upon receipt of such a
			 * message, the source node reduces its assumed PMTU for the path based
			 * on the MTU of the constricting hop as reported in the Packet Too Big
			 * message.*/
			pmtu = ntoh32(icmp6_err->data);
			
			/* A node MUST NOT increase its estimate of the Path MTU in response to
			 * the contents of a Packet Too Big message. */
			if(nif->ipv6->pmtu > pmtu) nif->ipv6->pmtu = pmtu;
		}
		goto DROP;
	#endif
                break;
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
		default: return NETPP_DROP;
                }
		//netprot_notify(nif,pkt,prot_cmd,src_addr,dst_addr); /* Protocol notification.*/
		break;
	/*
	 * Parameter Problems.
	 */
	case FNET_ICMP6_TYPE_PARAM_PROB:
		switch(hdr->code){
		
		/* Protocol unreachable */
		case FNET_ICMP6_CODE_PP_NEXT_HEADER:
			prot_cmd = FNET_PROT_NOTIFY_UNREACH_PROTOCOL;
			
			/* Protocol notification.*/
			//netprot_notify(nif,pkt,prot_cmd,src_addr,dst_addr);
			break;
		default: return NETPP_DROP;
		}
		break;
	default: return NETPP_DROP;
	}
	
	
	return NETPP_DROP;
}

