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

int fastnet_openpktio(nif_table_t* table,const char* dev,odp_pool_t pool){
	odp_pktio_t             pktio;
	odp_pktio_param_t       pktio_p;
	odp_pktin_queue_param_t pktin_qp;
	nif_t*                  nif;
	odp_queue_t             loop;
	odp_queue_param_t       loop_p;
	int ret;
	
	if(table->max>=NET_NIFTAB_MAX_NIFS) return 0;
	odp_queue_param_init(&loop_p);
	loop_p.type     = ODP_QUEUE_TYPE_SCHED;
	loop_p.enq_mode = ODP_QUEUE_OP_MT;
	loop = odp_queue_create("loopback_queue",&loop_p);
	if(loop!=ODP_QUEUE_INVALID) return 0;
	
	nif = &(table->table[table->max]);
	nif->loopback = loop;
	
	/*
	 * Open network interface.
	 */
	odp_pktio_param_init(&pktio_p);
	pktio_p.in_mode = ODP_PKTIN_MODE_SCHED;
	pktio = odp_pktio_open(dev, pool, &pktio_p);
	if (pktio == ODP_PKTIO_INVALID) goto error2;
	
	/*
	 * Configure input-queues.
	 */
	odp_pktin_queue_param_init(&pktin_qp);
	pktin_qp.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	if (odp_pktin_queue_config(pktio, &pktin_qp)) goto error1;
	
	/*
	 * Configure output queues.
	 */
	if (odp_pktout_queue_config(pktio, NULL)) goto error1;
	
	/*
	 * Get output event queues
	 */
	ret = odp_pktout_event_queue(pktio,nif->output,NET_NIF_MAX_QUEUE);
	if(ret == 0) goto error1;
	if(ret>NET_NIF_MAX_QUEUE) nif->num_queues = NET_NIF_MAX_QUEUE;
	else nif->num_queues = ret;
	
	/*
	 * Start device.
	 */
	ret = odp_pktio_start(pktio);
	if (ret != 0) goto error1;
	
	/* Complete NIF structure. */
	nif->pktio = pktio;
	
	/*
	 * Increment size pointer.
	 */
	table->max++;
	
	return 1;
error1:
	odp_pktio_close(pktio);
error2:
	odp_queue_destroy(loop);
	return 0;
}

