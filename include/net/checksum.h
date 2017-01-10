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

uint16_t fastnet_checksum(odp_packet_t pkt,uint32_t offset,uint32_t cksuminit,nif_t* nif,uint32_t offload_flags);
uint16_t fastnet_ip_ph(ipv4_addr_t src,ipv4_addr_t dst,uint8_t prot);
uint16_t fastnet_ip6_ph(ipv6_addr_t src,ipv6_addr_t dst,uint8_t prot);

