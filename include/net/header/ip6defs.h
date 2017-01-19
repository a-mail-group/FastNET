/*
 *   Copyright 2016-2017 Simon Schmidt
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
#pragma once

#include <net/header/ip6.h>

/**************************************************************************/ /*!
 * @brief   Size of the string buffer that will contain
 *          null-terminated ASCII string of an IPv6 address
 *          in standard ":" notation.
 * @see fnet_inet_ntop
 * @showinitializer
 ******************************************************************************/
#define IP6_ADDR_STR_SIZE       sizeof("abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd")

#define IP6_HEADSIZE        40u     /* IPv6 Header size.  */

#define IP6_DEFAULT_MTU     1280u   /* Minimum IPv6 datagram size which    
                                     * must be supported by all IPv6 hosts */

/****************************************************************
 *
 * Helpful macros.
 *
 *****************************************************************/
#define IP6_ADDR_INIT(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16)      \
    { .addr = { (a1), (a2), (a3), (a4), (a5), (a6), (a7), (a8), (a9), (a10), (a11), (a12), (a13), (a14), (a15), (a16) }}

/*
 * Definition of some useful macros to handle IP6 addresses
 */
#define IP6_ADDR_ANY_INIT                      IP6_ADDR_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
#define IP6_ADDR_LOOPBACK_INIT                 IP6_ADDR_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
#define IP6_ADDR_NODELOCAL_ALLNODES_INIT       IP6_ADDR_INIT(0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
#define IP6_ADDR_INTFACELOCAL_ALLNODES_INIT    IP6_ADDR_INIT(0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
#define IP6_ADDR_LINKLOCAL_ALLNODES_INIT       IP6_ADDR_INIT(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
#define IP6_ADDR_LINKLOCAL_ALLROUTERS_INIT     IP6_ADDR_INIT(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02)
#define IP6_ADDR_LINKLOCAL_ALLV2ROUTERS_INIT   IP6_ADDR_INIT(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16)
#define IP6_ADDR_LINKLOCAL_PREFIX_INIT         IP6_ADDR_INIT(0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

#define IP6_ADDR_IS_MULTICAST(a) (((a).addr[0]) == 0xffU)

/*
 * RFC 4291 2.7 :
 *
 *    +--------+----+----+---------------------------------------------+
 *    |   8    |  4 |  4 |                  112 bits                   |
 *    +--------+----+----+---------------------------------------------+
 *    |11111111|flgs|scop|                  group ID                   |
 *    +--------+----+----+---------------------------------------------+
 *
 *    We are only interested in the lower 4 bits (scop).
 */
#define IP6_ADDR_MULTICAST_SCOPE(a) (((a).addr[1])&0xf)

#define IP6_ADDR_IS_UNSPECIFIED(a) \
    (((((a).addr32[0]) == 0U) &&	\
      (((a).addr32[1]) == 0U) &&	\
      (((a).addr32[2]) == 0U) &&	\
      (((a).addr32[3]) == 0U)))

#define IP6_ADDR_IS_LINKLOCAL(a)	\
    ((((a).addr[0]) == 0xfeU) && ((((a).addr[1]) & 0xc0U) == 0x80U))

#define IP6_ADDR_IS_SITELOCAL(a)	\
    ((((a).addr[0]) == 0xfeU) && ((((a).addr[1]) & 0xc0U) == 0xc0U))
