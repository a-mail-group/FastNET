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

#if 0
#include <stdio.h>
#define DEBUG(x) printf(#x " = %d\n",x)
#define DBGPF(...) printf(__VA_ARGS__)
#else
#define DEBUG(x) (void)0
#define DBGPF(...) (void)0
#endif

int fastnet_niftable_prepare(nif_table_t* table,odp_instance_t instance) {
	table->workers = odp_cpumask_default_worker(&(table->cpumask), NET_MAXTHREAD);
	DEBUG( table->workers==0 );
	if(table->workers==0) return 0;
	table->instance = instance;
	return 1;
}


nif_t* fastnet_openpktio(nif_table_t* table,const char* dev,odp_pool_t pool) {
	odp_pktio_t              pktio;
	odp_pktio_param_t        pktio_p;
	odp_pktin_queue_param_t  pktin_qp;
	odp_pktout_queue_param_t pktout_qp;
	nif_t*                   nif;
	odp_queue_t              loop;
	odp_queue_param_t        loop_p;
	int ret;
	
	if(table->max>=NET_NIFTAB_MAX_NIFS) return 0;
	odp_queue_param_init(&loop_p);
	loop_p.type     = ODP_QUEUE_TYPE_SCHED;
	loop_p.enq_mode = ODP_QUEUE_OP_MT;
	loop = odp_queue_create("loopback_queue",&loop_p);
	DEBUG( loop==ODP_QUEUE_INVALID );
	if(loop==ODP_QUEUE_INVALID) return 0;
	odp_queue_context_set(loop,table,sizeof(*table));
	
	nif = &(table->table[table->max]);
	nif->loopback = loop;
	nif->ipv4 = 0;
	
	/*
	 * Open network interface.
	 */
	odp_pktio_param_init(&pktio_p);
	pktio_p.in_mode = ODP_PKTIN_MODE_SCHED;
	pktio_p.out_mode = ODP_PKTOUT_MODE_QUEUE;
	pktio = odp_pktio_open(dev, pool, &pktio_p);
	DEBUG( pktio == ODP_PKTIO_INVALID );
	if (pktio == ODP_PKTIO_INVALID) goto error2;
	
	/*
	 * Configure input-queues.
	 */
	#define CONFIGURE_PKTIN do{                              \
	odp_pktin_queue_param_init(&pktin_qp);                   \
	pktin_qp.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC; \
	}while(0)
	CONFIGURE_PKTIN;
	DBGPF("pktin_qp.num_queues %d -> %d\n",(int)(pktin_qp.num_queues),table->workers);
	pktin_qp.num_queues             = table->workers;
	if (odp_pktin_queue_config(pktio, &pktin_qp)) {
		DBGPF("packet-input multi-queue setup failed. Fallback to single-queue\n");
		CONFIGURE_PKTIN;
		if (odp_pktin_queue_config(pktio, &pktin_qp)) {
			DBGPF("odp_pktin_queue_config(pktio, &pktin_qp) FAILED\n");
			goto error1;
		}
	}
	DBGPF("odp_pktin_queue_config(pktio, &pktin_qp) SUCCEED\n");
	
	/*
	 * Configure output queues.
	 */
	#define CONFIGURE_PKTOUT do{\
	odp_pktout_queue_param_init(&pktout_qp);\
	}while(0)
	
	CONFIGURE_PKTOUT;
	
	DBGPF("pktout_qp.num_queues %d -> %d\n",(int)(pktout_qp.num_queues),table->workers);
	pktout_qp.num_queues = table->workers;
	if (odp_pktout_queue_config(pktio, &pktout_qp)){
		DBGPF("packet-output multi-queue setup failed. Fallback to single-queue\n");
		CONFIGURE_PKTOUT;
		if (odp_pktout_queue_config(pktio, &pktout_qp)){
			DBGPF("odp_pktout_queue_config(pktio, &pktout_qp) FAILED\n");
			goto error1;
		}
	}
	DBGPF("odp_pktout_queue_config(pktio, NULL) SUCCEED\n");
	
	/*
	 * Get output event queues
	 */
	ret = odp_pktout_event_queue(pktio,nif->output,NET_NIF_MAX_QUEUE);
	DBGPF("ret = odp_pktout_event_queue(pktio,nif->output,NET_NIF_MAX_QUEUE);\n");
	DEBUG(ret == 0);
	DEBUG(ret);
	if(ret == 0) goto error1;
	if(ret>NET_NIF_MAX_QUEUE) nif->num_queues = NET_NIF_MAX_QUEUE;
	else nif->num_queues = ret;
	
	/*
	 * Start device.
	 */
	ret = odp_pktio_start(pktio);
	DBGPF("ret = odp_pktio_start(pktio);\n");
	DEBUG(ret == 0);
	if (ret != 0) goto error1;
	
	/* Complete NIF structure. */
	nif->pktio = pktio;
	
	/*
	 * Increment size pointer.
	 */
	table->max++;
	
	return nif;
error1:
	odp_pktio_close(pktio);
error2:
	odp_queue_destroy(loop);
	return 0;
}

