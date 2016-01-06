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

/*
 * This file is derived from FNET as of version 3.0.0
 */

#pragma once

#include "ip_addr.h"

/************************************************************************
*    Definitions of five different classes.
*************************************************************************/
#define FNET_IP4_CLASS_A(i)     !((i).addr[0]&0x80)
#define FNET_IP4_CLASS_A_NET    FNET_HTONL(0xff000000U)

#define FNET_IP4_CLASS_B(i)     (((i).addr[0]&0xC0) == 0x80)
#define FNET_IP4_CLASS_B_NET    FNET_HTONL(0xffff0000U)

#define FNET_IP4_CLASS_C(i)     (((i).addr[0]&0xE0) == 0xC0)
#define FNET_IP4_CLASS_C_NET    FNET_HTONL(0xffffff00U)

#define FNET_IP4_CLASS_D(i)     (((i).addr[0]&0xF0) == 0xE0)
#define FNET_IP4_CLASS_D_NET    FNET_HTONL(0xf0000000U)

/* Host groups are identified by class D IP addresses.*/
#define FNET_IP4_ADDR_IS_MULTICAST(addr)   FNET_IP4_CLASS_D(addr)

#define FNET_IP4_ADDR_IS_UNSPECIFIED(addr) !(addr).as_odp

#define FNET_IP4_CLASS_E(i)     (((i).addr[0]&0xF0) == 0xF0)
#define FNET_IP4_EXPERIMENTAL(i) FNET_IP4_CLASS_E(i)
#define FNET_IP4_BADCLASS(i)     FNET_IP4_CLASS_E(i)

#define FNET_IP4_ADDR1(ipaddr)   ((fnet_uint8_t)(fnet_ntohl(ipaddr) >> 24U) & 0xffU)
#define FNET_IP4_ADDR2(ipaddr)   ((fnet_uint8_t)(fnet_ntohl(ipaddr) >> 16U) & 0xffU)
#define FNET_IP4_ADDR3(ipaddr)   ((fnet_uint8_t)(fnet_ntohl(ipaddr) >> 8U) & 0xffU)
#define FNET_IP4_ADDR4(ipaddr)   ((fnet_uint8_t)(fnet_ntohl(ipaddr)) & 0xffU)

#define FSTN_IP4_BROADCAST      0xFFFFFFFFU


/*----------------  IPv6 ----------------------*/

#define FNET_IP6_ADDR_INIT(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16)      \
                            {{ (a1), (a2), (a3), (a4), (a5), (a6), (a7), (a8), (a9), (a10), (a11), (a12), (a13), (a14), (a15), (a16) }}

/*
 * Definition of some useful macros to handle IP6 addresses
 */
#define FNET_IP6_ADDR_ANY_INIT                      FNET_IP6_ADDR_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
#define FNET_IP6_ADDR_LOOPBACK_INIT                 FNET_IP6_ADDR_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
#define FNET_IP6_ADDR_NODELOCAL_ALLNODES_INIT       FNET_IP6_ADDR_INIT(0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
#define FNET_IP6_ADDR_INTFACELOCAL_ALLNODES_INIT    FNET_IP6_ADDR_INIT(0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
#define FNET_IP6_ADDR_LINKLOCAL_ALLNODES_INIT       FNET_IP6_ADDR_INIT(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
#define FNET_IP6_ADDR_LINKLOCAL_ALLROUTERS_INIT     FNET_IP6_ADDR_INIT(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02)
#define FNET_IP6_ADDR_LINKLOCAL_ALLV2ROUTERS_INIT   FNET_IP6_ADDR_INIT(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16)
#define FNET_IP6_ADDR_LINKLOCAL_PREFIX_INIT         FNET_IP6_ADDR_INIT(0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

static const fstn_ipv6_t in6addr_any = FNET_IP6_ADDR_ANY_INIT;
static const fstn_ipv6_t in6addr_loopback = FNET_IP6_ADDR_LOOPBACK_INIT;


/* Unspecified.*/
#define FNET_IP6_ADDR_IS_UNSPECIFIED(a) FSTN_IPV6_EQUALS((a),in6addr_any)

/* Loopback.*/
#define FNET_IP6_ADDR_IS_LOOPBACK(a) FSTN_IPV6_EQUALS((a),in6addr_loopback)

/* Multicast. */
#define FNET_IP6_ADDR_IS_MULTICAST(a)	((a).addr[0] == 0xffU)

/* Unicast Scope.*/
#define FNET_IP6_ADDR_IS_LINKLOCAL(a)	\
    	(((a).addr[0] == 0xfeU) && (((a).addr[0] & 0xc0U) == 0x80U))
#define FNET_IP6_ADDR_IS_SITELOCAL(a)	\
    	(((a).addr[0] == 0xfeU) && (((a).addr[0] & 0xc0U) == 0xc0U))


typedef struct {
	uint16_t num;
	fstn_ipv6_t* tab;
} ipv6_table_s;


