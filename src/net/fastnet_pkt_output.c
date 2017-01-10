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
#include <net/packet_output.h>

netpp_retcode_t fastnet_pkt_output(odp_packet_t pkt,nif_t *dest){
	int qi = odp_thread_id() % dest->num_queues;
	return odp_queue_enq(dest->output[qi], odp_packet_to_event (pkt))?NETPP_DROP:NETPP_CONSUMED;
}

netpp_retcode_t fastnet_pkt_loopback(odp_packet_t pkt,nif_t *dest){
	return odp_queue_enq(dest->loopback, odp_packet_to_event (pkt))?NETPP_DROP:NETPP_CONSUMED;
}

