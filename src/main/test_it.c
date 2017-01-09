/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2017, Simon Schmidt
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 *
 * Simple ODP example.
 */
#include <stdio.h>
#include <stdlib.h>

#include <odp_api.h>
#include <odp/helper/linux.h>

#define EXAMPLE_ABORT(...) do{ printf(__VA_ARGS__); abort(); }while(0)

#define PRIu64 "%p"

#define caseof(VAL,BODY)  case VAL: BODY; break;

static odp_pktio_t create_pktio(const char *dev, odp_pool_t pool)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	/* Open a packet IO instance */
	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		EXAMPLE_ABORT("Error: pktio create failed for %s\n", dev);

	odp_pktin_queue_param_init(&pktin_param);

	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	if (odp_pktin_queue_config(pktio, &pktin_param))
		EXAMPLE_ABORT("Error: pktin config failed for %s\n", dev);

	if (odp_pktout_queue_config(pktio, NULL))
		EXAMPLE_ABORT("Error: pktout config failed for %s\n", dev);

	ret = odp_pktio_start(pktio);
	if (ret != 0)
		EXAMPLE_ABORT("Error: unable to start %s\n", dev);

	printf("  created pktio:" PRIu64
	       ", dev:%s, queue mode (ATOMIC queues)\n"
	       "  \tdefault pktio:" PRIu64 "\n",
	       (void*)(uintptr_t)odp_pktio_to_u64(pktio), dev,
	       (void*)(uintptr_t)odp_pktio_to_u64(pktio));

	return pktio;
}

#define PRINT_INT(expr) "\t" #expr " = %d\n"
static int sched_thread(void *arg){
	odp_event_t ev;
	odp_packet_t pkt;
	
	for(;;){
		ev = odp_schedule(NULL, ODP_SCHED_WAIT);
		if(odp_unlikely(ev == ODP_EVENT_INVALID)) continue;
			
		switch(odp_event_type(ev)){
		caseof(ODP_EVENT_TIMEOUT, odp_timeout_free(odp_timeout_from_event(ev)) )
		case ODP_EVENT_PACKET:
			pkt = odp_packet_from_event(ev);
			
			printf("Packet{\n"
			"\thas L2=%d,L3=%d,L4=%d\n"
			"\tlayer3=%s%s%s\n"
			"\tlayer4=%s%s%s%s\n"
			"}\n"
			,odp_packet_has_l2(pkt)
			,odp_packet_has_l3(pkt)
			,odp_packet_has_l4(pkt)
			,odp_packet_has_arp(pkt) ?"ARP":""
			,odp_packet_has_ipv4(pkt)?"IPv4":""
			,odp_packet_has_ipv6(pkt)?"IPv6":""
			
			,odp_packet_has_udp(pkt) ?"UDP":""
			,odp_packet_has_tcp(pkt) ?"TCP":""
			,odp_packet_has_sctp(pkt)?"SCTP":""
			,odp_packet_has_icmp(pkt)?"ICMP":""
			);
			odp_packet_free(pkt);
			break;
		caseof(ODP_EVENT_BUFFER,
			odp_buffer_free(odp_buffer_from_event(ev)) )
		caseof(ODP_EVENT_CRYPTO_COMPL,
			odp_crypto_compl_free(odp_crypto_compl_from_event(ev)) )
		}
	}
}

#define BUFFER_SIZE 1856
#define POOL_SIZE   (512*2048)

#define PAR_THRDS 16

int main(){
	int i,p;

	/* ---------------------Packet IO Vars.----------------------- */
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_instance_t instance;
	//odph_odpthread_params_t thr_params;
	odp_pktio_t pktio;
	
	/* ---------------------Thread Vars.----------------------- */
	odp_cpumask_t CM,TM;
	int nthreads = PAR_THRDS;
	odph_odpthread_t threads[PAR_THRDS];
	odph_odpthread_params_t tpar;
	
	
	/* ---------------------Packet IO Code.----------------------- */
	odp_init_global(&instance, NULL, NULL);
	odp_init_local(instance, ODP_THREAD_CONTROL);
	
	odp_pool_param_init(&params);
	params.pkt.seg_len = BUFFER_SIZE;
	params.pkt.len     = BUFFER_SIZE;
	params.pkt.num     = POOL_SIZE/BUFFER_SIZE;
	params.type        = ODP_POOL_PACKET;
	
	pool = odp_pool_create("packet_pool", &params);
	if (pool == ODP_POOL_INVALID) EXAMPLE_ABORT("Error: packet pool create failed.\n");
	
	odp_pool_print(pool);
	
	pktio = create_pktio("vmbridge0",pool);
	
	
	/* ---------------------Thread Vars.----------------------- */
	tpar.start = sched_thread;
	tpar.instance = instance;
	tpar.thr_type = ODP_THREAD_WORKER;
	
	nthreads = odp_cpumask_default_worker(&CM, nthreads);
	p = odp_cpumask_first(&CM);
	for (i = 0; i < nthreads; ++i) {
		odp_cpumask_zero(&TM);
		odp_cpumask_set(&TM,p);
		odph_odpthreads_create(&threads[i],&TM,&tpar);
		
		p = odp_cpumask_next(&CM, p);
	}
	
	for (i = 0; i < nthreads; ++i)
		odph_odpthreads_join(&threads[i]);
	
	odp_term_local();
	odp_term_global(instance);
	return 0;
}
