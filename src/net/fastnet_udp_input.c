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
#include <net/nif.h>
#include <net/types.h>
#include <net/_config.h>
#include <net/header/udphdr.h>

#include <net/in_tlp.h>

netpp_retcode_t fastnet_udp_input(odp_packet_t pkt){
	fnet_udp_header_t *uh = odp_packet_l4_ptr(pkt,NULL);
	
	NET_LOG("UDP datagram: %d->%d\n",(int)odp_be_to_cpu_16(uh->source_port),(int)odp_be_to_cpu_16(uh->destination_port));
	return NETPP_DROP;
}

