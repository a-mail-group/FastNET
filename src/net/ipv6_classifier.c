/*
 *   Copyright 2017 Simon Schmidt
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
#include <net/ipv6.h>
#include <net/header/ip6defs.h>
#include <net/ipv6_constants.h>

/************************************************************************
*     Policy Table (RFC3484)
*************************************************************************/
typedef struct fnet_ip6_if_policy_entry
{
    ipv6_addr_t prefix;             /* Prefix of an IP address. */
    int         prefix_length;      /* Prefix length (in bits). The number of leading bits in the Prefix that are valid. */
    uint32_t    precedence;         /* Precedence value used for sorting destination addresses.*/
    uint32_t    label;              /* The label value Label(A) allows for policies that prefer a particular
                                     * source address prefix for use with a destination address prefix.*/
} ip6_pte_t;

/* RFC3484 Default policy table:*/
static const ip6_pte_t ip6_pte[] =
{
    {IP6_ADDR_INIT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),          128,    50, 0},
    {IP6_ADDR_INIT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),          0,      40, 1},
    {IP6_ADDR_INIT(0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),    16,     30, 2},
    {IP6_ADDR_INIT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),          96,     20, 3},
    {IP6_ADDR_INIT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0),    96,     10, 4}
};
static const unsigned int ip6_pte_n = (sizeof(ip6_pte)/sizeof(ip6_pte_t));

static const uint8_t bit_mask[] = { 0x00, 0x80,0xC0,0xE0,0xF0, 0xF8,0xFC,0xFE,0xFF, };

static const ipv6_addr_t ip6_addr_loopback = IP6_ADDR_LOOPBACK_INIT;

uint32_t fastnet_ipv6_scope(ipv6_addr_t ip_addr){
	int32_t scope, result;
	
	//result = FNET_IP6_ADDR_SCOPE_GLOBAL;
	
	/* Local Host. */
	if(IP6_ADDR_IS_LINKLOCAL(ip_addr)) {
		return FNET_IP6_ADDR_SCOPE_LINKLOCAL;
	} else if(IP6_ADDR_IS_SITELOCAL(ip_addr)) {
		return FNET_IP6_ADDR_SCOPE_SITELOCAL;
	} else
	
	/* Multicast. */
	if(IP6_ADDR_IS_MULTICAST(ip_addr)) {
		scope = (int32_t)IP6_ADDR_MULTICAST_SCOPE(ip_addr);
		switch(scope) {
		case FNET_IP6_ADDR_SCOPE_INTERFACELOCAL:
			return FNET_IP6_ADDR_SCOPE_INTERFACELOCAL;
			break;
		case FNET_IP6_ADDR_SCOPE_LINKLOCAL:
			return FNET_IP6_ADDR_SCOPE_LINKLOCAL;
			break;
		case FNET_IP6_ADDR_SCOPE_SITELOCAL:
			return FNET_IP6_ADDR_SCOPE_SITELOCAL;
			break;
		default:
			break;
		}
	} else
	
	/* Loopback interface - special case. */
	if(IP6ADDR_EQ(ip_addr, ip6_addr_loopback)) {
		return FNET_IP6_ADDR_SCOPE_INTERFACELOCAL;
	}
	
	return FNET_IP6_ADDR_SCOPE_GLOBAL;
}

uint32_t fastnet_ipv6_policy_label(ipv6_addr_t ip_addr){
	int i, best_pref = 0,pref;
	
	uint32_t label = 0;
	
	for(i = 0; i<ip6_pte_n; ++i){
		pref = fastnet_ipv6_common_prefix(&ip6_pte[i].prefix,&ip_addr);
		if(ip6_pte[i].prefix_length < pref) continue;
		
		if(best_pref <= ip6_pte[i].prefix_length) continue;
		
		best_pref = ip6_pte[i].prefix_length;
		label = ip6_pte[i].label;
	}
	
	return label;
}

int fastnet_ipv6_common_prefix(const ipv6_addr_t *addr1,const ipv6_addr_t *addr2) {
	int i,j;
	uint8_t xb;
	
	for(i=0;i<15;++i)
		if(addr1->addr[i] != addr2->addr[i]) break;
	
	xb = addr1->addr[i] ^ addr2->addr[i];
	
	for(j=0;j<=8;++j) if(bit_mask[j]&xb) break;
	
	return (uint32_t)( (i*8) + j);
}


