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
#include <net/nif.h>
#include <net/types.h>
#include <net/header/ip.h>
#include <net/header/ip6.h>

typedef struct fastnet_ipv6_pair{
	ipv6_addr_t src,dst;
} fastnet_ipv6_pair_t;
struct fastnet_ipv4_pair{
	ipv4_addr_t src,dst;
};
typedef union fastnet_ip_pair{
	struct fastnet_ipv6_pair* ipv6;
	struct fastnet_ipv4_pair  ipv4;
} fastnet_ip_pair_t;

netpp_retcode_t fastnet_udp_output(odp_packet_t pkt, fastnet_ip_pair_t addrs, uint16_t srcport, uint16_t dstport, odp_bool_t isipv6);

