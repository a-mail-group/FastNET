/*
 *   Copyright 2016 Simon Schmidt
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
#pragma once

#include <odp_api.h>


#define FNET_IP6_OPTION_TYPE_PAD1   (0x00u)  /* The Pad1 option is used to insert 
                                             * one octet of padding into the Options area of a header.*/
#define FNET_IP6_OPTION_TYPE_PADN   (0x01u)  /* The PadN option is used to insert two or more octets of padding
                                             * into the Options area of a header. For N octets of padding, the
                                             * Opt Data Len field contains the value N-2, and the Option Data
                                             * consists of N-2 zero-valued octets. */

/* RFC 2460: The Option Type identifiers are internally encoded such that their
 * highest-order two bits specify the action that must be taken if the
 * processing IPv6 node does not recognize the Option Type:*/
#define FNET_IP6_OPTION_TYPE_UNRECOGNIZED_MASK          (0xC0u)

#define FNET_IP6_OPTION_TYPE_UNRECOGNIZED_SKIP          (0x00u)  /* 00 - skip over this option and continue processing the header.*/
#define FNET_IP6_OPTION_TYPE_UNRECOGNIZED_DISCARD       (0x40u)  /* 01 - discard the packet. */
#define FNET_IP6_OPTION_TYPE_UNRECOGNIZED_DISCARD_ICMP  (0x80u)  /* 10 - discard the packet and, regardless of whether or not the
                                                                 * packet's Destination Address was a multicast address, send an
                                                                 * ICMP Parameter Problem, Code 2, message to the packet's
                                                                 * Source Address, pointing to the unrecognized Option Type.*/
#define FNET_IP6_OPTION_TYPE_UNRECOGNIZED_DISCARD_UICMP (0xC0u)  /* 11 - discard the packet and, only if the packet's Destination
                                                                 * Address was not a multicast address, send an ICMP Parameter
                                                                 * Problem, Code 2, message to the packet's Source Address,
                                                                 * pointing to the unrecognized Option Type.*/


