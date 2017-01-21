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


#ifndef _NETICMP6_HEADERS_H_
#define _NETICMP6_HEADERS_H_

#include <odp_api.h>

/* ICMPv6 error messages:*/
#define FNET_ICMP6_TYPE_DEST_UNREACH                (1u)     /* Destination Unreachable. */
#define FNET_ICMP6_TYPE_PACKET_TOOBIG               (2u)     /* Packet Too Big. */
#define FNET_ICMP6_TYPE_TIME_EXCEED                 (3u)     /* Time Exceeded. */
#define FNET_ICMP6_TYPE_PARAM_PROB                  (4u)     /* Parameter Problem. */

/* ICMPv6 informational messages:*/
#define FNET_ICMP6_TYPE_ECHO_REQ                    (128u)   /* Echo Request. */
#define FNET_ICMP6_TYPE_ECHO_REPLY                  (129u)	/* Echo Reply. */

/* MLD messages (RFC2710):*/
#define FNET_ICMP6_TYPE_MULTICAST_LISTENER_QUERY    (130u)   /* Multicast Listener Query */
#define FNET_ICMP6_TYPE_MULTICAST_LISTENER_REPORT   (131u)   /* Multicast Listener Report */
#define FNET_ICMP6_TYPE_MULTICAST_LISTENER_DONE     (132u)   /* Multicast Listener Done */

/*  Neighbor Discovery defines five different ICMP packet types (RFC4861):*/
#define FNET_ICMP6_TYPE_ROUTER_SOLICITATION         (133u)   /* Router Solicitation. */
#define FNET_ICMP6_TYPE_ROUTER_ADVERTISEMENT        (134u)   /* Router Advertisement. */
#define FNET_ICMP6_TYPE_NEIGHBOR_SOLICITATION       (135u)   /* Neighbor Solicitation. */
#define FNET_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT      (136u)   /* Neighbor Advertisement. */
#define FNET_ICMP6_TYPE_REDIRECT                    (137u)   /* Redirect.*/

/* Destination Unreachable codes */
#define FNET_ICMP6_CODE_DU_NO_ROUTE                 (0u)     /* No route to destination. */
#define FNET_ICMP6_CODE_DU_ADMIN_PROHIBITED         (1u)     /* Communication with destination administratively prohibited. */
#define FNET_ICMP6_CODE_DU_BEYOND_SCOPE             (2u)     /* Beyond scope of source address.*/
#define FNET_ICMP6_CODE_DU_ADDR_UNREACH             (3u)     /* Address unreachable.*/
#define FNET_ICMP6_CODE_DU_PORT_UNREACH             (4u)     /* Port unreachable.*/
#define FNET_ICMP6_CODE_DU_ADDR_FAILED              (5u)     /* Source address failed ingress/egress policy.*/
#define FNET_ICMP6_CODE_DU_REJECT_ROUTE             (6u)     /* Reject route to destination.*/

/* Packet Too Big codes */
#define FNET_ICMP6_CODE_PTB                         (0u)

/* Time Exceeded codes */
#define FNET_ICMP6_CODE_TE_HOP_LIMIT                (0u)     /* Hop limit exceeded in transit.*/
#define FNET_ICMP6_CODE_TE_FRG_REASSEMBLY           (1u)     /* Fragment reassembly time exceeded.*/

/* Parameter Problem codes */
#define FNET_ICMP6_CODE_PP_HEADER                   (0u)     /* Erroneous header field encountered.*/
#define FNET_ICMP6_CODE_PP_NEXT_HEADER              (1u)     /* Unrecognized Next Header type encountered.*/
#define FNET_ICMP6_CODE_PP_OPTION                   (2u)     /* Unrecognized IPv6 option encountered.*/

#define NETICMP6_PROTOCOL_NUM     58   /* IPv6-ICMP = 58 */

/***********************************************************************
 * Generic ICMP packet header
 ***********************************************************************
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                         Message Body                          +
 * |                                                               |
 *
 ***********************************************************************/
typedef struct ODP_PACKED
{
    uint8_t   type ;      /* The type of the message.*/
    uint8_t   code ;      /* The code of the message.*/
    uint16_t  checksum ;  /* The checksum of the message.*/
} fnet_icmp6_header_t;

/***********************************************************************
 * ICMPv6 Echo packet
 ***********************************************************************
 * RFC4443 4:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Type       |       Code    |             Checksum          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Identifier        |       Sequence Number         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Data ...
 * +-+-+-+-+-
 ***********************************************************************/
typedef struct ODP_PACKED
{
    fnet_icmp6_header_t  icmp6_header    ;
    uint16_t        id                   ;
    uint16_t        seq_number           ;
} fnet_icmp6_echo_header_t;

/***********************************************************************
 * ICMPv6 Error packet
 ***********************************************************************/
typedef struct ODP_PACKED
{
    fnet_icmp6_header_t  icmp6_header    ;
    uint32_t             data            ;
} fnet_icmp6_err_header_t;


#endif

