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
 * RFC-4861 10. Protocol Constants.
 * Router constants:
 *          MAX_INITIAL_RTR_ADVERT_INTERVAL  16 seconds
 *          MAX_INITIAL_RTR_ADVERTISEMENTS    3 transmissions
 *          MAX_FINAL_RTR_ADVERTISEMENTS      3 transmissions
 *          MIN_DELAY_BETWEEN_RAS             3 seconds
 *          MAX_RA_DELAY_TIME                 .5 seconds
 *
 * Host constants:
 *          MAX_RTR_SOLICITATION_DELAY        1 second
 *          RTR_SOLICITATION_INTERVAL         4 seconds
 *          MAX_RTR_SOLICITATIONS             3 transmissions
 *
 * Node constants:
 *          MAX_MULTICAST_SOLICIT             3 transmissions
 *          MAX_UNICAST_SOLICIT               3 transmissions
 *          MAX_ANYCAST_DELAY_TIME            1 second
 *          MAX_NEIGHBOR_ADVERTISEMENT        3 transmissions
 *          REACHABLE_TIME               30,000 milliseconds
 *          RETRANS_TIMER                 1,000 milliseconds
 *          DELAY_FIRST_PROBE_TIME            5 seconds
 *          MIN_RANDOM_FACTOR                 .5
 *          MAX_RANDOM_FACTOR                 1.5
 */

void fastnet_ipv6_init(struct ipv6_nif_struct *ipv6){
	odp_spinlock_init(&(ipv6->fields_lock));
	odp_spinlock_init(&(ipv6->address_lock));
	odp_spinlock_init(&(ipv6->multicast_lock));
	
	ipv6->hop_limit = 64;
	ipv6->mtu = IP6_DEFAULT_MTU;
	ipv6->pmtu = IP6_DEFAULT_MTU;
	ipv6->base_reachable_time = 30000;
	ipv6->reachable_time = 30000;
	ipv6->retrans_timer = 1000;
	ipv6->disabled = 0;
	ipv6->pmtu_on = 0;
}

