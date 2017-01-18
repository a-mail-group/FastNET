/*
 *   Copyright 2016-2017 Simon Schmidt
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

#include <net/ipv6.h>
#include <net/header/ip6defs.h>
#include <odp_api.h>
#include <net/_config.h>

struct ipv6_nif_struct;

static const ipv6_addr_t   ip6_addr_any                      = IP6_ADDR_ANY_INIT;
static const ipv6_addr_t   ip6_addr_loopback                 = IP6_ADDR_LOOPBACK_INIT;
static const ipv6_addr_t   ip6_addr_nodelocal_allnodes       = IP6_ADDR_NODELOCAL_ALLNODES_INIT;
static const ipv6_addr_t   ip6_addr_linklocal_allnodes       = IP6_ADDR_LINKLOCAL_ALLNODES_INIT;
static const ipv6_addr_t   ip6_addr_linklocal_allrouters     = IP6_ADDR_LINKLOCAL_ALLROUTERS_INIT;
static const ipv6_addr_t   ip6_addr_linklocal_allv2routers   = IP6_ADDR_LINKLOCAL_ALLV2ROUTERS_INIT;
static const ipv6_addr_t   ip6_addr_linklocal_prefix         = IP6_ADDR_LINKLOCAL_PREFIX_INIT;

int fastnet_ipv6_deactivated(struct ipv6_nif_struct *ipv6){
	if(odp_unlikely(ipv6==NULL)) return 1;
	return ipv6->disabled;
}

/*
 * Returns non-0 if the address is directed at ourself.
 */
int fastnet_ipv6_addr_is_self(struct ipv6_nif_struct *ipv6, ipv6_addr_t *addr){
	int i;
	
	if( IP6_ADDR_IS_MULTICAST(*addr) ){
		switch( IP6_ADDR_MULTICAST_SCOPE(*addr) ) {
		/*
		 * RFC 4291 2.7
		 * 
		 * Nodes must not originate a packet to a multicast address whose scop
		 * field contains the reserved value 0; if such a packet is received, it
		 * must be silently dropped.
		 */
		case 0:
		/*
		 * RFC 4291 - Errata ID: 3480
		 *
		 * Section 2.7 says: 
		 *  Interface-Local scope spans only a single interface on a node
		 *  and is useful only for loopback transmission of multicast.
		 * 
		 * It should say:
		 *  Interface-Local scope spans only a single interface on a node 
		 *  and is useful only for loopback transmission of multicast.
		 *  Packets with interface-local scope received from another node 
		 *  must be discarded.
		 *
		 * It should be explicitly stated that interface-local scoped multicast packets
		 * received from the link must be discarded.
		 * The BSD implementation currently does this, but not Linux.
		 * http://www.ietf.org/mail-archive/web/ipv6/current/msg17154.html 
		 */
		case 1:
			return 0;
		}
		return -1;
	}
	
	if(odp_unlikely(ipv6==NULL)) return 0;
	
	for(i=0;i<IPV6_NIF_ADDR_MAX;++i){
		/* Skip NOT_USED addresses. */
		if( !ipv6->addrs[i].used ) continue;
		
		/* Match the current Network address. */
		if( IP6ADDR_EQ(*addr,ipv6->addrs[i].address) ) return -1;
	}
	return 0;
}


int fastnet_ipv6_addr_is_own_ip6_solicited_multicast(struct ipv6_nif_struct *ipv6, ipv6_addr_t *addr){
	int i;
	
	if(odp_unlikely(ipv6==NULL)) return 0;
	
	for(i=0;i<IPV6_NIF_ADDR_MAX;++i){
		/* Skip NOT_USED addresses. */
		if( !ipv6->addrs[i].used ) continue;
		
		/* Match the current Solicited Multicast address. */
		if( IP6ADDR_EQ(*addr,ipv6->addrs[i].solicited_multicast_addr) ) return -1;
	}
	return 0;
}
