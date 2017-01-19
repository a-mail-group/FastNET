/*
 *   Copyright 2016-2017 Simon Schmidt
 *   Copyright 2011-2016 by Andrey Butok. FNET Community.
 *   Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
 *   Copyright 2003 by Andrey Butok. Motorola SPS.
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
#include <net/header/icmp.h>
#include <net/header/iphdr.h>
#include <net/checksum.h>
#include <net/header/layer4.h>
#include <net/_config.h>
#include <net/defaults.h>
#include <net/safe_packet.h>

typedef struct{
	ipv4_addr_t src,dst;
} ip_pair_t;

enum
{
	UNREACH_IP,
	UNREACH_L4,
};

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
struct ipv4_nif_struct* getIpv4(odp_packet_t pkt, nif_t** pnif){
	nif_t* nif;
	struct ipv4_nif_struct* ipv4;
	*pnif = nif = odp_packet_user_ptr(pkt);
	return odp_likely(nif != NULL) ? nif->ipv4 : NULL;
}

static inline
netpp_retcode_t get_ip_pair(ip_pair_t* pair,odp_packet_t pkt,struct ipv4_nif_struct* ipv4){
	fnet_ip_header_t *ip;
	
	ip = fastnet_safe_l3(pkt,sizeof(fnet_ip_header_t));
	if(odp_unlikely(!ip)) return NETPP_DROP;
	
	/*
	 * Source address must not be any multicast/broadcast address.
	 */
	if(odp_unlikely(fastnet_ip_broadcast(ipv4,ip->source_addr))) return NETPP_DROP;
	
	pair->src = ip->source_addr;
	pair->dst = ip->desination_addr;
	return NETPP_CONTINUE;
}

static inline
void add_response_header(ip_pair_t* pair,odp_packet_t pkt,uint32_t pktlen,uint32_t offset){
	fnet_ip_header_t* ip;
	
	if(offset >= sizeof(fnet_ip_header_t)){
		odp_packet_l3_offset_set(pkt,offset-sizeof(fnet_ip_header_t));
		ip = odp_packet_l3_ptr(pkt,NULL);
	}else{
		ip = odp_packet_push_head(pkt,sizeof(fnet_ip_header_t)-offset);
		odp_packet_l3_offset_set(pkt,0);
		odp_packet_l4_offset_set(pkt,sizeof(fnet_ip_header_t));
	}
	
	/*
	 * The IP version is 4 and the Default IP header length is 5.
	 * Packet into a single byte, it is 0x45.
	 */
	ip->version__header_length = 0x45;
	ip->tos                    = FNET_IP_TOS_NORMAL;
	ip->total_length           = odp_cpu_to_be_16(pktlen+sizeof(fnet_ip_header_t));
	ip->id                     = 0;
	ip->flags_fragment_offset  = 0;
	ip->ttl                    = DATAGRAM_TTL;
	ip->protocol               = IP_PROTOCOL_ICMP;
	ip->checksum               = 0;
	/*
	 * In the response header, Source and Destination addresses are swapped.
	 */
	ip->source_addr            = pair->dst;
	ip->desination_addr        = pair->src;
}


netpp_retcode_t fastnet_icmpv4_input(odp_packet_t pkt){
	ip_pair_t               pair;
	netpp_retcode_t         ret;
	fnet_icmp_header_t*     hdr;
	fnet_prot_notify_t      prot_cmd;
	uint32_t                pktlen,pktoff;
	struct ipv4_nif_struct* ipv4;
	nif_t*                  nif;
	//int                 ;
	uint16_t                chksum;
	
	ipv4 = getIpv4(pkt,&nif);
	
	ret = get_ip_pair(&pair,pkt,ipv4);
	
	if(odp_unlikely(ret != NETPP_CONTINUE)) return ret;
	
	hdr = fastnet_safe_l4(pkt,sizeof(fnet_icmp_header_t));
	if(odp_unlikely(!hdr)) return NETPP_DROP;
	
	pktoff = odp_packet_l4_offset(pkt);
	pktlen = odp_packet_len(pkt);
	pktlen -= pktoff;
	
	/*
	 * Checksum test.
	 */
	if(odp_unlikely( fastnet_checksum(pkt,pktoff,0,odp_packet_user_ptr(pkt),0) != 0 )) return NETPP_DROP;
	
	switch(hdr->type){
	/**************************
	 * ICMP Request Processing
	 **************************/
	case FNET_ICMP_ECHO:
		/*
		 * An ICMP Echo Request destined to an IP broadcast or IP
		 * multicast address MAY be silently discarded.(RFC1122)
		 */
		if(odp_unlikely(fastnet_ip_broadcast(ipv4,pair.dst))) return NETPP_DROP;
		
		hdr->type = FNET_ICMP_ECHOREPLY;
		hdr->checksum = 0;
		hdr->checksum = fastnet_checksum(pkt,pktoff,0,odp_packet_user_ptr(pkt),0);
		
		add_response_header(&pair,pkt,pktlen,pktoff);
		
		NET_LOG("ICMP ECHO: %08x %08x\n",pair.src,pair.dst);
		
		return fastnet_ip_output(pkt,NULL);
		break;
		
	/**************************
	 * ICMP Error Processing
	 **************************/
	case FNET_ICMP_UNREACHABLE:
		switch(hdr->code){
		case FNET_ICMP_UNREACHABLE_NET:           /* net unreachable */
		case FNET_ICMP_UNREACHABLE_NET_UNKNOWN:   /* unknown net */
		case FNET_ICMP_UNREACHABLE_NET_PROHIB:    /* prohibited access */
		case FNET_ICMP_UNREACHABLE_TOSNET:        /* bad tos for net */
			prot_cmd = FNET_PROT_NOTIFY_UNREACH_NET;
			break;
		case FNET_ICMP_UNREACHABLE_HOST:          /* host unreachable */
		case FNET_ICMP_UNREACHABLE_HOST_UNKNOWN:  /* unknown host */
		case FNET_ICMP_UNREACHABLE_ISOLATED:      /* src host isolated */
		case FNET_ICMP_UNREACHABLE_HOST_PROHIB:   /* ditto */
		case FNET_ICMP_UNREACHABLE_TOSHOST:       /* bad tos for host */
			prot_cmd = FNET_PROT_NOTIFY_UNREACH_HOST;
			break;
		
		case FNET_ICMP_UNREACHABLE_PROTOCOL:      /* protocol unreachable */
			prot_cmd = FNET_PROT_NOTIFY_UNREACH_PROTOCOL;
			break;
		
		case FNET_ICMP_UNREACHABLE_PORT:          /* port unreachable */
			prot_cmd = FNET_PROT_NOTIFY_UNREACH_PORT;
			break;
		
		case FNET_ICMP_UNREACHABLE_SRCFAIL:       /* source route failed */
			prot_cmd = FNET_PROT_NOTIFY_UNREACH_SRCFAIL;
			break;
		case FNET_ICMP_UNREACHABLE_NEEDFRAG:      /* fragmentation needed and DF set*/
			prot_cmd = FNET_PROT_NOTIFY_MSGSIZE;
			break;
		
		default: return NETPP_DROP;
                }
		//netprot_notify(nif,pkt,prot_cmd,src_addr,dst_addr); /* Protocol notification.*/
		break;
	
	case FNET_ICMP_TIMXCEED:
		switch(hdr->code) {
		case FNET_ICMP_TIMXCEED_INTRANS:          /* time to live exceeded in transit (ttl==0)*/
			prot_cmd = FNET_PROT_NOTIFY_TIMXCEED_INTRANS;
			break;
		
		case FNET_ICMP_TIMXCEED_REASS:            /* fragment reassembly time exceeded (ttl==0)*/
			prot_cmd = FNET_PROT_NOTIFY_TIMXCEED_REASS;
			break;
		
		default: return NETPP_DROP;
                }

                //netprot_notify(nif,pkt,prot_cmd,src_addr,dst_addr); /* Protocol notification.*/
                break;
	
	case FNET_ICMP_PARAMPROB:                       /* Parameter Problem Message.*/
		if(hdr->code > 1u) return NETPP_DROP;
		
		prot_cmd = FNET_PROT_NOTIFY_PARAMPROB;
		//netprot_notify(nif,pkt,prot_cmd,src_addr,dst_addr); /* Protocol notification.*/
		break;
	
	case FNET_ICMP_SOURCEQUENCH:                    /* Source Quench Message; packet lost, slow down.*/
		if(hdr->code) return NETPP_DROP;
		
		prot_cmd = FNET_PROT_NOTIFY_QUENCH;
		//netprot_notify(nif,pkt,prot_cmd,src_addr,dst_addr); /* Protocol notification.*/
		break;
	/************************
	 * Ignore others
	 ************************/
	/*
	case FNET_ICMP_REDIRECT:
	case FNET_ICMP_ECHOREPLY:
	case FNET_ICMP_ROUTERADVERT:
	case FNET_ICMP_ROUTERSOLICIT:
	case FNET_ICMP_TSTAMPREPLY:
	case FNET_ICMP_IREQREPLY:
	case FNET_ICMP_MASKREPLY:*/
	/*
	 * XXX Forward to Application, maybe.
	 */
	default: return NETPP_DROP;
	}
	
	return NETPP_DROP;
}
