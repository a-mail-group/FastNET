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

typedef struct {
	ipv6_addr_t src_ip, dst_ip;
	uint16_t src_port,dst_port;
	nif_t * nif;
	uint8_t layer3_version; /* 4 = IPv4; 6 = IPv6 */
	uint8_t layer4_version; /* next_header or protocol-id */
} socket_key_t;

/*
 * Obtains the IP-level fields of the socket key.
 *
 * The fields src_port, dst_port and layer4_version are left to be filled by the callee.
 */
netpp_retcode_t fastnet_socket_key_obtain_ip(odp_packet_t pkt, socket_key_t *key);

/*
 * Obtains the IP-level fields of the socket key, and the ports.
 *
 * The field layer4_version is left to be filled by the callee.
 */
netpp_retcode_t fastnet_socket_key_obtain(odp_packet_t pkt, socket_key_t *key);

