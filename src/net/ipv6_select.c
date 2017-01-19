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
#include <net/ipv6_constants.h>

int fastnet_ipv6_addr_select(struct ipv6_nif_struct *ipv6, ipv6_addr_t *src, ipv6_addr_t *dest) {
	int i,ibest;
	int best_cp=0,cp;
	uint32_t best_scope,scope;
	uint32_t best_label,label;
	ipv6_addr_t best_addr;
	
	uint32_t targ_scope = fastnet_ipv6_scope(*dest);
	uint32_t targ_label = fastnet_ipv6_policy_label(*dest);
	
	ibest = IPV6_NIF_ADDR_MAX;
	
	if(odp_unlikely(ipv6==NULL)) return 0;
	
	/*
	 * RFC3484:   5:   "Source Address Selection"
	 */
	for(i=0;i<IPV6_NIF_ADDR_MAX;++i) {
		if( !ipv6->addrs[i].used ) continue;
		/*
		 * In this implementation, SA is prefered by default
		 *
		 * IF SB is prefered over SA, THEN DO: SA := SB!
		 */
		
		/*
		 * Rule 1: Prefer same address.
		 * If SA = D, then prefer SA.  Similarly, if SB = D, then prefer SB.
		 */
		cp = fastnet_ipv6_common_prefix(&ipv6->addrs[i].address,dest);
		
		/*
		 * IF CommonPrefixLen(SB, D) = 128 THEN SB = D
		 */
		if(cp == 128){
			ibest = i;
			best_addr = ipv6->addrs[i].address;
			
			/* Terminate the algorithm. */
			break;
		}
		
		/*
		 * Loop rule: Grab the first address, if we don't have one.
		 * Or in other words: If SA is non-existing, then prefer SB.
		 */
		if( ibest==IPV6_NIF_ADDR_MAX ){
			ibest = i;
			best_addr = ipv6->addrs[i].address;
			best_scope = fastnet_ipv6_scope(best_addr);
			best_label = fastnet_ipv6_policy_label(best_addr);
			best_cp = cp;
			continue;
		}
		
		/*
		 * Rule 2: Prefer appropriate scope.
		 * 
		 * If Scope(SA) < Scope(SB): If Scope(SA) < Scope(D), then prefer SB and
		 * otherwise prefer SA.  Similarly, if Scope(SB) < Scope(SA): If
		 * Scope(SB) < Scope(D), then prefer SA and otherwise prefer SB.
		 */
		
		scope = fastnet_ipv6_scope(ipv6->addrs[i].address);
		if(
			/* If Scope(SA) < Scope(SB): If Scope(SA) < Scope(D), then prefer SB. */
			((best_scope < scope) && (best_scope < targ_scope)) ||
			/* If Scope(SB) < Scope(SA): If Scope(SB) < Scope(D), ... otherwise prefer SB.*/
			(scope < best_scope) && (scope >= targ_scope)
		) {
			ibest = i;
			best_addr = ipv6->addrs[i].address;
			best_scope = scope;
			best_label = fastnet_ipv6_policy_label(best_addr);
			best_cp = cp;
			continue;
		}
		
		/* Rule 3:  Avoid deprecated addresses. */
		
		/* Rule 4:  Prefer home addresses. */
		
		/* Rule 5:  Prefer outgoing interface. */
		
		/*
		 * Rule 6: Prefer matching label.
		 * If Label(SA) = Label(D) and Label(SB) <> Label(D), then prefer SA.
		 * Similarly, if Label(SB) = Label(D) and Label(SA) <> Label(D), then
		 * prefer SB.
		 */
		
		label = fastnet_ipv6_policy_label(ipv6->addrs[i].address);
		
		/* If Label(SB) = Label(D) and Label(SA) <> Label(D), then prefer SB. */
		if( (label == targ_label) && (best_label != targ_label) ){
			ibest = i;
			best_addr = ipv6->addrs[i].address;
			best_scope = scope;
			best_label = label;
			best_cp = cp;
			continue;
		}
		
		/* Rule 7: Prefer temporary addresses. */
		
		/*
		 * Rule 8: Use longest matching prefix.
		 * If CommonPrefixLen(SA, D) > CommonPrefixLen(SB, D), then prefer SA.
		 * Similarly, if CommonPrefixLen(SB, D) > CommonPrefixLen(SA, D), then
		 * prefer SB.
		 */
		if( cp > best_cp ){
			ibest = i;
			best_addr = ipv6->addrs[i].address;
			best_scope = scope;
			best_label = label;
			best_cp = cp;
			continue;
		}
	}
	
	if( ibest==IPV6_NIF_ADDR_MAX ) return 0;
	
	*src = best_addr;
	
	return 1;
}

