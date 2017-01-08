/*
 *   Copyright 2016 Simon Schmidt
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

#include <net/niftable.h>

#define BURST_SIZE 1024

#define caseof(VAL,BODY)  case VAL: BODY; break;

static inline
void fastnet_packet_input(odp_packet_t pkt,odp_queue_t queue,nif_table_t* tab){
	nif_t *nif = NULL;
	odp_pktio_t pktio;
	netpp_retcode_t retcode;
	int i,n;
	
	if(odp_likely(queue != ODP_QUEUE_INVALID))
		nif = odp_queue_context(queue);
	if(odp_likely(nif == NULL)) {
		pktio = odp_packet_input(pkt);
		if (odp_unlikely(pktio == ODP_PKTIO_INVALID)) goto error;
		
		for(i=0,n=(tab->max);i<n;++i) {
			if(odp_unlikely(tab->table[i].pktio == pktio)) {
				nif = &(tab->table[i]);
				break;
			}
		}
		if (odp_unlikely(nif == NULL)) goto error;
		
		odp_packet_user_ptr_set(pkt,nif);
	}
	retcode = tab->function(pkt);
	if(odp_likely(retcode==NETPP_CONSUMED)) return;
	
error:
	odp_packet_free(pkt);
}

void *fastnet_eventlist(void *arg){
	odp_event_t ev;
	odp_queue_t src_queue;
	odp_event_t events[BURST_SIZE];
	int n_event,i;
	nif_table_t* tab = arg;
	
	for(;;){
		n_event = odp_schedule_multi(&src_queue, ODP_SCHED_WAIT, events, BURST_SIZE);
		for(i=0;i<n_event;++i){
			ev = events[i];
			if(odp_unlikely(ev == ODP_EVENT_INVALID)) continue;
			
			switch(odp_event_type(ev)){
			caseof(ODP_EVENT_TIMEOUT, odp_timeout_free(odp_timeout_from_event(ev)) )
			caseof(ODP_EVENT_PACKET,  fastnet_packet_input(odp_packet_from_event(ev),src_queue,tab) )
			caseof(ODP_EVENT_BUFFER,
				odp_buffer_free(odp_buffer_from_event(ev)) )
			caseof(ODP_EVENT_CRYPTO_COMPL,
				odp_crypto_compl_free(odp_crypto_compl_from_event(ev)) )
			}
		}
	}
}

