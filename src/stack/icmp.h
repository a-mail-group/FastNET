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

#pragma once

#include <odp.h>
#include "typedefs.h"

/*
 * This file is derived from FNET as of version 3.0.0
 */

/************************************************************************
*     Definition of type and code field values.
*************************************************************************/
#define FNET_ICMP_ECHOREPLY                (0u)  /* Echo reply message.*/
#define FNET_ICMP_UNREACHABLE              (3u)  /* Destination Unreachable Message:*/
#define FNET_ICMP_UNREACHABLE_NET          (0u)  /*    -net unreachable*/
#define FNET_ICMP_UNREACHABLE_HOST         (1u)  /*    -host unreachable*/
#define FNET_ICMP_UNREACHABLE_PROTOCOL     (2u)  /*    -protocol unreachable*/
#define FNET_ICMP_UNREACHABLE_PORT         (3u)  /*    -port unreachable*/
#define FNET_ICMP_UNREACHABLE_NEEDFRAG     (4u)  /*    -fragmentation needed and DF set*/
#define FNET_ICMP_UNREACHABLE_SRCFAIL      (5u)  /*    -source route failed*/
#define FNET_ICMP_UNREACHABLE_NET_UNKNOWN  (6u)  /*    -unknown net*/
#define FNET_ICMP_UNREACHABLE_HOST_UNKNOWN (7u)  /*    -unknown host*/
#define FNET_ICMP_UNREACHABLE_ISOLATED     (8u)  /*    -src host isolated*/
#define FNET_ICMP_UNREACHABLE_NET_PROHIB   (9u)  /*    -prohibited access*/
#define FNET_ICMP_UNREACHABLE_HOST_PROHIB  (10u) /*    -ditto*/
#define FNET_ICMP_UNREACHABLE_TOSNET       (11u) /*    -bad tos for net*/
#define FNET_ICMP_UNREACHABLE_TOSHOST      (12u) /*    -bad tos for host*/
#define FNET_ICMP_SOURCEQUENCH             (4u)  /* Source Quench Message, packet lost, slow down.*/
#define FNET_ICMP_REDIRECT                 (5u)  /* Redirect Message:*/
#define FNET_ICMP_REDIRECT_NET             (0u)  /*    -redirect datagrams for the Network*/
#define FNET_ICMP_REDIRECT_HOST            (1u)  /*    -redirect datagrams for the Host*/
#define FNET_ICMP_REDIRECT_TOSNET          (2u)  /*    -redirect datagrams for the Type of Service and Network*/
#define FNET_ICMP_REDIRECT_TOSHOST         (3u)  /*    -redirect datagrams for the Type of Service and Host*/
#define FNET_ICMP_ECHO                     (8u)  /* Echo message.*/
#define FNET_ICMP_ROUTERADVERT             (9u)  /* Router advertisement.*/
#define FNET_ICMP_ROUTERSOLICIT            (10u) /* Router solicitation.*/
#define FNET_ICMP_TIMXCEED                 (11u) /* Time Exceeded Message:*/
#define FNET_ICMP_TIMXCEED_INTRANS         (0u)  /*    -time to live exceeded in transit (ttl==0).*/
#define FNET_ICMP_TIMXCEED_REASS           (1u)  /*    -fragment reassembly time exceeded (ttl==0).*/
#define FNET_ICMP_PARAMPROB                (12u) /* Parameter Problem Message: */
#define FNET_ICMP_PARAMPROB_IPHEDER        (0u)  /*    -IP header bad.*/
#define FNET_ICMP_PARAMPROB_OPTABSENT      (1u)  /*    -required option missing.*/
#define FNET_ICMP_TSTAMP                   (13u) /* Timestamp message (request)*/
#define FNET_ICMP_TSTAMPREPLY              (14u) /* Timestamp reply message*/
#define FNET_ICMP_IREQ                     (15u) /* Information request message*/
#define FNET_ICMP_IREQREPLY                (16u) /* Information reply message*/
#define FNET_ICMP_MASKREQ                  (17u) /* Address mask request.*/
#define FNET_ICMP_MASKREPLY                (18u) /* Address mask reply.*/


/*
 * @brief processes an icmp packet
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function processes an icmp packet.
 */
void fstn_icmp_input(odp_packet_t pkt, thr_s* thr);

/*
 * @brief sends an icmp packet
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function sends an icmp packet.
 */
void fstn_icmp_output(odp_packet_t pkt, thr_s* thr);

/*
 * @brief sends an icmp error message
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function sends an icmp error message.
 */
void fstn_icmp_error(thr_s* thr, uint16_t type,uint16_t code,odp_packet_t cause);


