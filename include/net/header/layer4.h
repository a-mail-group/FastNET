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


#define IP_PROTOCOL_HOPOPTS 0x00 /* Hop by hop.*/
#define IP_PROTOCOL_ICMP    0x01
#define IP_PROTOCOL_IGMP    0x02
#define IP_PROTOCOL_TCP     0x06
#define IP_PROTOCOL_UDP     0x11
#define IP_PROTOCOL_ROUTE   0x2B /* IPv6 Routing header. */
#define IP_PROTOCOL_GRE     0x2F
#define IP_PROTOCOL_FRAG    0x2C /* IPv6 Fragment */
#define IP_PROTOCOL_ESP     0x32 /* IPSec Encapsulated Payload */
#define IP_PROTOCOL_AH      0x33 /* IPSec Authentication Header */
#define IP_PROTOCOL_ICMP6   0x3A
#define IP_PROTOCOL_INVALID 0xFF /* Reserved invalid by IANA */


