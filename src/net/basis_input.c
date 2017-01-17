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

#include <net/niftable.h>

#define BURST_SIZE 1024

#define caseof(VAL,BODY)  case VAL: BODY; break;
#define caseelse(BODY) default: BODY; break;

static inline
void free_one(odp_event_t ev);

static inline
void free_all(odp_event_t* events,int n_event);

static inline
void* queue_context(odp_queue_t queue);

static inline
void fastnet_packet_input(odp_packet_t pkt,nif_table_t* tab,nif_t *nif){
	odp_pktio_t pktio;
	netpp_retcode_t retcode;
	int i,n;
	
	odp_packet_user_ptr_set(pkt,nif);
	
	retcode = tab->function(pkt);
	if(odp_likely(retcode==NETPP_CONSUMED)) return;
	
error:
	odp_packet_free(pkt);
}

int fastnet_eventlist(void *arg){
	odp_event_t ev;
	odp_queue_t src_queue;
	void* context;
	odp_event_t events[BURST_SIZE];
	int n_event,i;
	nif_table_t* tab = arg;
	
	for(;;){
		n_event = odp_schedule_multi(&src_queue, ODP_SCHED_WAIT, events, BURST_SIZE);
		context = queue_context(src_queue);
		
		if(odp_unlikely(context==NULL)){
			free_all(events,n_event);
			continue;
		}
		
		for(i=0;i<n_event;++i){
			ev = events[i];
			if(odp_unlikely(ev == ODP_EVENT_INVALID)) continue;
			
			switch(odp_event_type(ev)){
			caseof(ODP_EVENT_PACKET,
				fastnet_packet_input(odp_packet_from_event(ev),tab,(nif_t*)context) )
			caseelse( free_one(ev) )
			}
		}
	}
	return 0;
}

/* --------------------------------------------------------------- */

static inline
void free_one(odp_event_t ev){
	switch(odp_event_type(ev)){
	caseof(ODP_EVENT_TIMEOUT,      odp_timeout_free(odp_timeout_from_event(ev)) )
	caseof(ODP_EVENT_PACKET,       odp_packet_free(odp_packet_from_event(ev)) )
	caseof(ODP_EVENT_BUFFER,       odp_buffer_free(odp_buffer_from_event(ev)) )
	caseof(ODP_EVENT_CRYPTO_COMPL, odp_crypto_compl_free(odp_crypto_compl_from_event(ev)) )
	}
}

static inline
void free_all(odp_event_t* events,int n_event){
	int i;
	odp_event_t ev;
	for(i=0;i<n_event;++i){
		ev = events[i];
		if(odp_unlikely(ev == ODP_EVENT_INVALID)) continue;
		free_one(ev);
	}
}

static inline
void* queue_context(odp_queue_t queue){
	if(odp_unlikely( queue == ODP_QUEUE_INVALID)) return NULL;
	return odp_queue_context(queue);
}
