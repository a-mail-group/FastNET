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
}

typedef struct ODP_PACKED {
	odph_icmphdr_t header;
	uint32be_t ip;
} fstn_icmp_4_t;

typedef struct ODP_PACKED {
	odph_icmphdr_t header;
	odph_ipv4hdr_t iph;
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
	const uint32_t          hdr_err_length = sizeof(fstn_icmp_err_t) /*+ ((FNET_IP_HEADER_GET_HEADER_LENGTH(ip_header) << 2) - sizeof(fnet_ip_header_t))*/; 
	const uint32_t          hdr_err_data_length = hdr_err_length+8u; /* 8 bytes is enough for transport protocol (port numbers).*/
	const uint32_t          pkt_shouldlen = hdr_err_data_length+odp_packet_l4_offset(pkt);
	
	
//	if(odp_packet_len(pkt) > pkt_shouldlen)
//		fstn_trimm_packet(pkt,pkt_shouldlen);

#if 0 // TODO: Propagate the messages to upper level.
    if((protocol = fnet_prot_find(AF_INET, SOCK_UNSPEC, (fnet_uint32_t)hdr_err->ip.protocol)) != 0)
    {
        if(protocol->prot_control_input)
        {
            struct sockaddr     err_src_addr;
            struct sockaddr     err_dest_addr;

            /* Prepare addreses for upper protocol.*/
            fnet_ip_set_socket_addr(netif, ip_header, &err_src_addr,  &err_dest_addr );

            fnet_netbuf_trim(&nb, (fnet_int32_t)(hdr_err_length)); /* Cut the ICMP error header.*/

            protocol->prot_control_input(prot_cmd, &err_src_addr, &err_dest_addr, nb);
        }
    }
#endif

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
    //uint32be_t          src_ip;
    //uint32be_t          dest_ip;
	fstn_ipv4_t         dest_ip;
	uint32_t            size;
	
	hdr = odp_packet_l4_ptr(pkt,&size);
	if(odp_unlikely( size<ODPH_ICMPHDR_LEN ))
		goto DISCARD;
	
	dest_ip.as_odp = ((odph_ipv4hdr_t*)odp_packet_l4_ptr(pkt,NULL))->src_addr;

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
//void fstn_icmp_output(odp_packet_t pkt, thr_s* thr);

/*
 * @brief sends an icmp error message
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function sends an icmp error message.
 */
//void fstn_icmp_error(thr_s* thr, uint16_t type,uint16_t code,odp_packet_t cause);


