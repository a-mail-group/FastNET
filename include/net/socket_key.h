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
#include <net/header/ip.h>
#include <net/header/ip6.h>

typedef struct {
	nif_t * nif;
	struct {
		ipv6_addr_t ip;
		uint16_t port;
	} src,dst;
	uint8_t layer3_version; /* 4 = IPv4; 6 = IPv6 */
	uint8_t layer4_version; /* next_header or protocol-id */
} socket_key_t;

