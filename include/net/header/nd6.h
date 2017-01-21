/*
 *   Copyright 2017 Simon Schmidt
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

#include <net/header/icmp6.h>
#include <net/header/ip6.h>


/*
 * RFC-4861 4.3.  Neighbor Solicitation Message Format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Type      |     Code      |          Checksum             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           Reserved                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   +                                                               +
 *   |                                                               |
 *   +                       Target Address                          +
 *   |                                                               |
 *   +                                                               +
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Options ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-
 */

typedef struct ODP_PACKED
{
	fnet_icmp6_header_t icmp6;
	uint32_t            _padding;
	ipv6_addr_t         target_addr;
} nd6_nsol_msg_t;



/*
 * RFC-4861 4.4.  Neighbor Advertisement Message Format
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     Type      |     Code      |          Checksum             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |R|S|O|                     Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    +                                                               +
 *    |                                                               |
 *    +                       Target Address                          +
 *    |                                                               |
 *    +                                                               +
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Options ...
 *    +-+-+-+-+-+-+-+-+-+-+-+-
 */

typedef struct ODP_PACKED
{
	fnet_icmp6_header_t icmp6;
	uint8_t             flags;
	uint8_t             _padding[3];
	ipv6_addr_t         target_addr;
} nd6_nadv_msg_t;

/*
 * R-Flag:
 *  Router flag.  When set, the R-bit indicates that
 *  the sender is a router.  The R-bit is used by
 *  Neighbor Unreachability Detection to detect a
 *  router that changes to a host.
 */
#define ND6_NADV_ROUTER 0x80

/*
 * S-Flag:
 *  Solicited flag.  When set, the S-bit indicates that
 *  the advertisement was sent in response to a
 *  Neighbor Solicitation from the Destination address.
 *  The S-bit is used as a reachability confirmation
 *  for Neighbor Unreachability Detection.  It MUST NOT
 *  be set in multicast advertisements or in
 *  unsolicited unicast advertisements.
 */
#define ND6_NADV_SOLICITED 0x40

/*
 * O-Flag:
 *  Override flag.  When set, the O-bit indicates that
 *  the advertisement should override an existing cache
 *  entry and update the cached link-layer address.
 *  When it is not set the advertisement will not
 *  update a cached link-layer address though it will
 *  update an existing Neighbor Cache entry for which
 *  no link-layer address is known.  It SHOULD NOT be
 *  set in solicited advertisements for anycast
 *  addresses and in solicited proxy advertisements.
 *  It SHOULD be set in other solicited advertisements
 *  and in unsolicited advertisements.
 */
#define ND6_NADV_OVERRIDE 0x20


/*
 * RFC-4861 4.1.  Router Solicitation Message Format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Type      |     Code      |          Checksum             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                            Reserved                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Options ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-
 */

typedef struct ODP_PACKED
{
	fnet_icmp6_header_t icmp6;
	uint32_t            _padding;
} nd6_rsol_msg_t;

/*
 * RFC-4861 4.2.  Router Advertisement Message Format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Type      |     Code      |          Checksum             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Reachable Time                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          Retrans Timer                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Options ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-
 */

typedef struct ODP_PACKED
{
	fnet_icmp6_header_t icmp6;
	uint8_t             cur_hop_limit;
	uint8_t             flags;
	uint16_t            router_lifetime;
	uint32_t            reachable_time;
	uint32_t            retrans_timer;
} nd6_radv_msg_t;

/*
 * M-flag:
 *  1-bit "Managed address configuration" flag.  When
 *  set, it indicates that addresses are available via
 *  Dynamic Host Configuration Protocol [DHCPv6].
 *  
 *  If the M flag is set, the O flag is redundant and
 *  can be ignored because DHCPv6 will return all
 *  available configuration information.
 */
#define ND6_RADV_MANAGED 0x80

/*
 * O-flag:
 *  1-bit "Other configuration" flag.  When set, it
 *  indicates that other configuration information is
 *  available via DHCPv6.  Examples of such information
 *  are DNS-related information or information on other
 *  servers within the network.
 */
#define ND6_RADV_OTHER 0x40


/*
 * RFC-4861 4.6.  Option Formats
 *
 *     0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |     Type      |    Length     |              ...              |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ~                              ...                              ~
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *
 *    Type           8-bit identifier of the type of option.  The
 *                   options defined in this document are:
 *
 *                         Option Name                             Type
 *
 *                      Source Link-Layer Address                    1
 *                      Target Link-Layer Address                    2
 *                      Prefix Information                           3
 *                      Redirected Header                            4
 *                      MTU                                          5
 *
 *    Length         8-bit unsigned integer.  The length of the option
 *                   (including the type and length fields) in units of
 *                   8 octets.  The value 0 is invalid.  Nodes MUST
 *                   silently discard an ND packet that contains an
 *                   option with length zero.
 */
typedef struct ODP_PACKED
{
	uint8_t type;
	uint8_t length;
} nd6_option_t;

/*
 * Source Link-Layer Address                    1
 * Target Link-Layer Address                    2
 * Prefix Information                           3
 * Redirected Header                            4
 * MTU                                          5
 */
#define ND6_OPTION_SLLA     1
#define ND6_OPTION_TLLA     2
#define ND6_OPTION_PREFIX   3
#define ND6_OPTION_REDIRECT 4
#define ND6_OPTION_MTU      5

