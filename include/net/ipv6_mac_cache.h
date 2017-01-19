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

#include <odp_api.h>
#include <net/types.h>
#include <net/nif.h>
#include <net/header/ip6.h>

void fastnet_initialize_ip6mac_cache();

netpp_retcode_t fastnet_ipv6_mac_lookup(nif_t* nif,ipv6_addr_t ipaddr,uint64_t* hwaddr,int *sendarp,odp_packet_t pkt);
odp_packet_t    fastnet_ipv6_mac_put(nif_t* nif,ipv6_addr_t ipaddr,uint64_t hwaddr,int create);

