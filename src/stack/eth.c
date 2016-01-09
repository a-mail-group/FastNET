/*
 *
 * Copyright 2016 Simon Schmidt
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "eth.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"
//#include <odp/helper/eth.h>

/*
 * @brief processes an input packet
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function processes an odp-packet.
 */
void fstn_pkt_input(odp_packet_t pkt, thr_s* thr){
	//odph_ethhdr_t *hdr;

	if(odp_unlikely(!odp_packet_has_eth(pkt)))
		goto DISCARD;
	//hdr = odp_packet_l2_ptr(pkt,NULL);
	if(odp_packet_has_arp(pkt))
		fstn_arp_input(pkt,thr);
	else if(odp_packet_has_ipv4(pkt))
		fstn_ipv4_input(pkt,thr);
	else if(odp_packet_has_ipv6(pkt))
		fstn_ipv6_input(pkt,thr);

	return;
	
	DISCARD:
	odp_packet_free(pkt);
}


