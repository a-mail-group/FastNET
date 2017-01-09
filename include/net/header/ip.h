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

#include <odp_api.h>

typedef uint32_t ipv4_addr_t;

#define IP4ADDR_EQ(a,b) ( (a) == (b) )

inline static ipv4_addr_t ipv4_addr_init(uint8_t a,uint8_t b,uint8_t c,uint8_t d){
	union {
		uint8_t  addr8[4];
		uint32_t addr32 ODP_PACKED;
	} addr = { .addr8={a,b,c,d} };
	return addr.addr32;
}


/* 169.254/16 prefix that is valid for Link-Local communication. RFC3927*/
#define IP4_ADDR_LINK_LOCAL_PREFIX      ipv4_addr_init(169,254,0,0)

/* IPv4 Link-Local broadcast. RFC3927*/
#define IP4_ADDR_LINK_LOCAL_BROADCAST   ipv4_addr_init(169,254,255,255)

#define IP4_ADDR_BROADCAST   ipv4_addr_init(255,255,255,255)

#define IP4_CHK_0 ipv4_addr_init(0x00,0,0,0)
#define IP4_CHK_8 ipv4_addr_init(0x80,0,0,0)
#define IP4_CHK_C ipv4_addr_init(0xC0,0,0,0)
#define IP4_CHK_E ipv4_addr_init(0xE0,0,0,0)
#define IP4_CHK_F ipv4_addr_init(0xF0,0,0,0)

#define IP4_CLASS_A(i) (( (i) & IP4_CHK_8 )==IP4_CHK_0)
#define IP4_CLASS_B(i) (( (i) & IP4_CHK_C )==IP4_CHK_8)
#define IP4_CLASS_C(i) (( (i) & IP4_CHK_E )==IP4_CHK_C)
#define IP4_CLASS_D(i) (( (i) & IP4_CHK_F )==IP4_CHK_E)
#define IP4_CLASS_E(i) (( (i) & IP4_CHK_F )==IP4_CHK_F)

/* Host groups are identified by class D IP addresses.*/
#define IP4_ADDR_IS_MULTICAST(i) IP4_CLASS_D(i)
#define IP4_ADDR_IS_UNSPECIFIED(i) ((i)==0u)

#define IP4_ADDR_IS_LINK_LOCAL(i) (( (i) & ipv4_addr_init(0xff,0xff,0,0) )==IP4_ADDR_LINK_LOCAL_PREFIX)

#define IP4_EXPERIMENTAL(i) IP4_CLASS_E(i)
#define IP4_BADCLASS(i)     IP4_CLASS_E(i)

#define IP4_CLASS_A_NETMASK ipv4_addr_init(255,0,0,0)
#define IP4_CLASS_B_NETMASK ipv4_addr_init(255,255,0,0)
#define IP4_CLASS_C_NETMASK ipv4_addr_init(255,255,255,0)
#define IP4_CLASS_D_NETMASK ipv4_addr_init(255,0,0,0)

#define IP4_ADDR_ANY_INIT ipv4_addr_init(0,0,0,0)


