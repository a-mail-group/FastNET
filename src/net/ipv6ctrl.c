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
#include <net/ipv6.h>
#include <net/header/ip6defs.h>

/*
 * Solicited-node Multicast Address prefix
 *
 * ff02:0000:0000:0000:0000:0001:ff00:0000 / 104
 * Last 3 bytes are copied from IP address.
 */
#define IP6_SOL_MULTICAST IP6_ADDR_INIT(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00);

static const uint64_t zero = 0;
//static const uint64_t infinity = ~0;

struct addr_creation_request {
	ipv6_addr_t  addr;
	uint8_t      prefix;
	uint64_t     lifetime;
	uint32_t     dad_transmit_counter;
	unsigned     type : 2;
	unsigned     state : 1;
};

/* Adds an IPv6 address to the interface. */
static
int ipv6_addr_add(struct ipv6_nif_struct *ipv6, struct addr_creation_request* req){
	int i,freei;
	const uint64_t infinity = ~zero;
	odp_time_t now;
	ipv6_addr_t ipaddr;
	ipv6_addr_t solicited = IP6_SOL_MULTICAST;
	
	now = odp_time_global();
	
	ipaddr = req->addr;
	
	solicited.addr[13] = ipaddr.addr[13];
	solicited.addr[14] = ipaddr.addr[14];
	solicited.addr[15] = ipaddr.addr[15];
	
	freei = IPV6_NIF_ADDR_MAX;
	
	for(i=0;i<IPV6_NIF_ADDR_MAX;++i){
		if( !ipv6->addrs[i].used ){
			freei = i;
			break;
		}
	}
	if(freei == IPV6_NIF_ADDR_MAX) return 0;
	
	ipv6->addrs[i].address                  = ipaddr;
	ipv6->addrs[i].solicited_multicast_addr = solicited;
	ipv6->addrs[i].creation_time            = now;
	ipv6->addrs[i].lifetime                 = req->lifetime;
	ipv6->addrs[i].prefix_length            = req->prefix;
	ipv6->addrs[i].dad_transmit_counter     = req->dad_transmit_counter;
	ipv6->addrs[i].state_time               = now;
	ipv6->addrs[i].type                     = req->type;
	ipv6->addrs[i].state                    = req->state;
	ipv6->addrs[i].used                     = 1;
	return 1;
}

/* Adds an IPv6 address to the interface. */
int fastnet_ipv6_addr_add(struct ipv6_nif_struct *ipv6, ipv6_addr_t *addr,uint8_t prefix){
	struct addr_creation_request req = {
		.addr = *addr,
		.prefix = prefix,
		.lifetime = ~zero,
		.dad_transmit_counter = 3,
		.type = FASTNET_IP6_ADDR_TYPE_MANUAL,
		.state = FASTNET_IP6_ADDR_TENTATIVE,
	};
	return ipv6_addr_add(ipv6,&req);
}

