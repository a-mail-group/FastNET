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

/*********************************************************************
* IP packet header
**********************************************************************
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |Version| Traffic Class |           Flow Label                  |
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |         Payload Length        |  Next Header  |   Hop Limit   |
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |                                                               |
*   +                                                               +
*   |                                                               |
*   +                         Source Address                        +
*   |                                                               |
*   +                                                               +
*   |                                                               |
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |                                                               |
*   +                                                               +
*   |                                                               |
*   +                      Destination Address                      +
*   |                                                               |
*   +                                                               +
*   |                                                               |
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**********************************************************************/
typedef struct ODP_PACKED
{
    uint32_t   version_tclass_flowl;   /* 4-bit Internet Protocol version number = 6, 8-bit traffic class field, 20-bit flow label. */
    uint16_t   length              ;   /* Length of the IPv6
                                        * payload, i.e., the rest of the packet following
                                        * this IPv6 header, in octets. */
    uint8_t   next_header          ;   /* Identifies the type of header
                                        * immediately following the IPv6 header.  Uses the
                                        * same values as the IPv4 Protocol field [RFC-1700
                                        * et seq.].*/
    uint8_t   hop_limit            ;   /* Decremented by 1 by
                                        * each node that forwards the packet. The packet
                                        * is discarded if Hop Limit is decremented to
                                        * zero. */
    ipv6_addr_t source_addr        ;   /* 128-bit address of the originator of the packet. */
    ipv6_addr_t destination_addr   ;   /* 128-bit address of the intended recipient of the
                                        * packet (possibly not the ultimate recipient, if
                                        * a Routing header is present). */
} fnet_ip6_header_t;

#define IPV6_HDR_LENGTH_OFFSET 4

