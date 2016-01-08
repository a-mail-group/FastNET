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
#include "ip_addr_ext.h"
#include "prot.h"
#include <odp/helper/icmp.h>
#include <odp/helper/ip.h>
#include "generic.h"

/*
 * This file is derived from FNET as of version 3.0.0
 */

/* This file is work in progress! */

static inline void fstn_swap_ip_addr(odp_packet_t pkt, thr_s* thr) {
	odph_ipv4hdr_t* hdr = odp_packet_l3_ptr(pkt,NULL);
	hdr->dst_addr = hdr->src_addr;
	hdr->src_addr = thr->netif->ipv4_address;
	hdr->ttl      = 0;
}

typedef struct ODP_PACKED {
	odph_icmphdr_t header;
	uint32be_t ip;
} fstn_icmp_4_t;

typedef struct ODP_PACKED {
	odph_icmphdr_t header;
	odph_ipv4hdr_t iph;
	uint16be_t src_port;
	uint16be_t dst_port;
} fstn_icmp_err_t;

/*
 * NAME: fnet_icmp_notify_protocol
 *
 * DESCRIPTION: Upper protocol notification..
 */
static void fstn_icmp_notify_protocol(thr_s *thr, fnotify_t prot_cmd, odp_packet_t pkt)
{
	uint32_t size;
	fstn_icmp_err_t         *hdr_err = odp_packet_l4_ptr(pkt,&size);
	if(odp_unlikely( size<sizeof(fstn_icmp_err_t) ))
		goto DISCARD;
	odph_ipv4hdr_t          *ip_header = &hdr_err->iph;
	fstn_control_param_t ctrl;

	ctrl.src_port = hdr_err->src_port;
	ctrl.dst_port = hdr_err->dst_port;
	ctrl.src_ip.ipv4 = ip_header->src_addr;
	ctrl.dst_ip.ipv4 = ip_header->dst_addr;
	ctrl.protocol = ip_header->proto;
	ctrl.prot_cmd = prot_cmd;
	ctrl.v6 = 0; /* 0 = IPv4 */
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
void fstn_icmp_input(odp_packet_t pkt, thr_s* thr){
	odph_icmphdr_t      *hdr;
    fnotify_t           prot_cmd;
	fstn_ipv4_t         dest_ip;
	uint32_t            size;
	
	hdr = odp_packet_l4_ptr(pkt,&size);
	if(odp_unlikely( size<ODPH_ICMPHDR_LEN ))
		goto DISCARD;
	
	dest_ip.as_odp = ((odph_ipv4hdr_t*)odp_packet_l4_ptr(pkt,NULL))->dst_addr;

	switch(hdr->type){
            /**************************
             * ICMP Request Processing
             **************************/
            case FNET_ICMP_ECHO:
				/* An ICMP Echo Request destined to an IP broadcast or IP
				* multicast address MAY be silently discarded.(RFC1122)*/
                if(
					(dest_ip.as_odp == FSTN_IP4_BROADCAST) ||
					(dest_ip.as_odp == thr->netif->ipv4_netbroadcast) ||
					FNET_IP4_ADDR_IS_MULTICAST(dest_ip))
						goto DISCARD;
				

                hdr->type = FNET_ICMP_ECHOREPLY;

				fstn_swap_ip_addr(pkt, thr);
                fstn_icmp_output(pkt, thr);
                break;
#if 0 /* Optional functionality.*/                
            /************************
             * Time Stamp Query 
             ************************/
            case FNET_ICMP_TSTAMP:
 
                /* The header must reside in contiguous area of memory. */
                if(fnet_netbuf_pullup(&nb, sizeof(fnet_icmp_timestamp_header_t)) == FNET_ERR)
                {
                    goto DISCARD;
                }

                hdr = nb->data_ptr;

                hdr->type = FNET_ICMP_TSTAMPREPLY;
                /* All times are in milliseconds since the stack timer start modulo 1 day. 
                * The high-order bit is set as the time value is recorded in nonstandard units. */
                ((fnet_icmp_timestamp_header_t *)hdr)->receive_timestamp
                    = fnet_htonl(((fnet_timer_ticks() * FNET_TIMER_PERIOD_MS) % (24 * 60 * 60 * 1000)) | (0x80000000));

                dest_ip = netif->ip4_addr.address;

                fnet_icmp_output(netif, dest_ip, src_ip, nb);
                break;
#endif
#if 1 /* Optional functionality.*
            /************************
             * Address Mask Query
             ************************/
            case FNET_ICMP_MASKREQ:
                /* check size error */
                if(odp_unlikely( size<sizeof(fstn_icmp_4_t) ))
					goto DISCARD;

                hdr->type = FNET_ICMP_MASKREPLY;

                ((fstn_icmp_4_t *)hdr)->ip = thr->netif->ipv4_subnetmask;

                fstn_swap_ip_addr(pkt, thr);
                fstn_icmp_output(pkt, thr);
                break;
#endif
            /**************************
             * ICMP Error Processing
             **************************/
            case FNET_ICMP_UNREACHABLE:
                switch(hdr->code)
                {
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

                    default:
                        goto DISCARD;
                }
                fstn_icmp_notify_protocol(thr, prot_cmd, pkt);  /* Protocol notification.*/
                break;
            case FNET_ICMP_TIMXCEED:
                switch(hdr->code)
                {
                    case FNET_ICMP_TIMXCEED_INTRANS:          /* time to live exceeded in transit (ttl==0)*/
                        prot_cmd = FNET_PROT_NOTIFY_TIMXCEED_INTRANS;
                        break;

                    case FNET_ICMP_TIMXCEED_REASS:            /* fragment reassembly time exceeded (ttl==0)*/
                        prot_cmd = FNET_PROT_NOTIFY_TIMXCEED_REASS;
                        break;

                    default:
                        goto DISCARD;
                }

                fstn_icmp_notify_protocol(thr, prot_cmd, pkt);  /* Protocol notification.*/
                break;
            case FNET_ICMP_PARAMPROB:                       /* Parameter Problem Message.*/
                if(hdr->code > 1u)
                {
                    goto DISCARD;
                }

                prot_cmd = FNET_PROT_NOTIFY_PARAMPROB;
                fstn_icmp_notify_protocol(thr, prot_cmd, pkt);  /* Protocol notification.*/
                break;
            case FNET_ICMP_SOURCEQUENCH:                    /* Source Quench Message; packet lost, slow down.*/
                if(hdr->code)
                {
                    goto DISCARD;
                }

                prot_cmd = FNET_PROT_NOTIFY_QUENCH;
                fstn_icmp_notify_protocol(thr, prot_cmd, pkt);  /* Protocol notification.*/
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
            default:
                goto DISCARD;
                
        }/* switch(hdr->type) */

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
void fstn_icmp_output(odp_packet_t pkt, thr_s* thr){
	uint32_t size;
	if(odp_unlikely(!fstn_packet_cut_l2(pkt)))
		goto DISCARD;

	odph_icmphdr_t *hdr = odp_packet_l4_ptr(pkt,&size);
	hdr->chksum = 0u;
	hdr->chksum = odp_chksum(hdr, size);

	((odph_ipv4hdr_t*)odp_packet_l3_ptr(pkt,NULL))->proto = ODPH_IPPROTO_ICMP;

	fstn_ipv4_output(pkt,thr);

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
void fstn_icmp_error(thr_s* thr, uint8_t type, uint8_t code, odp_packet_t cause){
	uint32_t size_errorpkt;
	uint32_t size;
	uint8_t ctype;

	fstn_ipv4_t src,dst;
	odph_ipv4hdr_t *iph  = odp_packet_l3_ptr(cause,&size);
	size_errorpkt = (ODPH_IPV4HDR_IHL(iph->ver_ihl)<<2)+8;

	src.as_odp = iph->src_addr;
	dst.as_odp = iph->dst_addr;

	/* Do not send error if not the first fragment of message (RFC1122)*/
	if(ODPH_IPV4HDR_FRAG_OFFSET(iph->frag_offset)>0)
		goto DISCARD;

	/* Do not send error on ICMP error messages*/
	if(odp_packet_has_icmp(cause)){
		ctype = ((odph_icmphdr_t*)odp_packet_l4_ptr(cause,NULL))->type;
		if( odp_unlikely(!FNET_ICMP_IS_QUERY_TYPE(ctype)) )
			goto DISCARD;
	}

	/* Do not send error on a datagram whose source address does not define a single
	 * host -- e.g., a zero address, a loopback address, a
	 * broadcast address, a multicast address, or a Class E
	 * address.*/
	if(odp_unlikely(
		(dst.as_odp == thr->netif->ipv4_netbroadcast) ||
		(src.as_odp == thr->netif->ipv4_netbroadcast) ||
		(FNET_IP4_ADDR_IS_MULTICAST(dst)) || (FNET_IP4_ADDR_IS_MULTICAST(src)) ||
		(FNET_IP4_CLASS_E(dst)) ||
		(dst.as_odp == FSTN_IP4_BROADCAST) || (src.as_odp == FSTN_IP4_BROADCAST)
	))
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
	if(type == FNET_ICMP_PARAMPROB){
		*((uint8_t*)(&icmp->un)) = code;
		code = 0;
	}else if(code == FNET_ICMP_UNREACHABLE_NEEDFRAG) {
		icmp->un.frag.mtu = odp_cpu_to_be_16( thr->netif->mtu );
	}

	icmp->type = type;
	icmp->code = code;

	odph_ipv4hdr_t *niph = odp_packet_push_head(pkt,sizeof(odph_ipv4hdr_t));
	niph->ttl = 0;
	niph->dst_addr = iph->src_addr;
	niph->src_addr = iph->dst_addr;

	odp_packet_has_l3_set(pkt,1);
	odp_packet_has_ipv4_set(pkt,1);
	odp_packet_l3_offset_set(pkt,0);
	odp_packet_l4_offset_set(pkt,sizeof(odph_ipv4hdr_t));

	fstn_icmp_output(pkt,thr);

	DISCARD:
	odp_packet_free(cause);
}


