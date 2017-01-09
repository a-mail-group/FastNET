/*
 *   Copyright 2016 Simon Schmidt
 *   Copyright 2011-2016 by Andrey Butok. FNET Community.
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
#include <net/ipv4.h>
#include <odp_api.h>

int fastnet_ip_broadcast(struct ipv4_nif_struct *ipv4,ipv4_addr_t addr){
	if(
		IP4ADDR_EQ(addr,IP4_ADDR_BROADCAST)|| /* Limited broadcast */
		IP4ADDR_EQ(addr,0)||
		IP4ADDR_EQ(addr,IP4_ADDR_LINK_LOCAL_BROADCAST) /* Link-local broadcast (RFC3927)*/
	) return 1;
	if(odp_unlikely(!ipv4) ) return 0; /* Null-Pointer check */
	if(
		IP4ADDR_EQ(addr,ipv4->netbroadcast)||
		IP4ADDR_EQ(addr,ipv4->subnetbroadcast)||
		IP4ADDR_EQ(addr,ipv4->subnet)
	) return 1;
	return 0;
}

int fastnet_ip_onlink(struct ipv4_nif_struct *ipv4,ipv4_addr_t addr){
	if(odp_unlikely(!ipv4) ) return 0; /* Null-Pointer check */
	return (
		/*
		 * Is the IPv4 address on-link?
		 */
		IP4ADDR_EQ( (ipv4->subnetmask & addr) , ipv4->subnet ) ||
		/* RFC3927: If the destination address is in the 169.254/16 prefix, then the sender
		 * MUST send its packet directly to the destination on the same physical link.  This MUST be
		 * done whether the interface is configured with a Link-Local or a routable IPv4 address.
		 */
		IP4_ADDR_IS_LINK_LOCAL( addr )
	);
}

int fastnet_ip_ishost(struct ipv4_nif_struct *ipv4,ipv4_addr_t addr) {
	if(odp_unlikely(!ipv4) ) return 0; /* Null-Pointer check */
	return IP4ADDR_EQ(addr,ipv4->address);
}

