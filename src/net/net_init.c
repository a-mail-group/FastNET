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
#include <string.h>
#include <net/std_lib.h>
#include <net/std_defs.h>
#include <net/mac_addr_ldst.h>
#include <net/requirement.h>

#if 0
#include <stdio.h>
#define DEBUG(x) printf(#x " = %d\n",x)
#define DBGPF(...) printf(__VA_ARGS__)
#else
#define DEBUG(x) (void)0
#define DBGPF(...) (void)0
#endif

#define BUFFER_SIZE 1856
#define POOL_SIZE   (512*2048)

int fastnet_pools_init(uint32_t pktsize,uint32_t pktnum,uint32_t poutsize,uint32_t poutnum){
	odp_pool_param_t params;
	odp_pool_t pool;
	
	/* ------------  Pool used by the NIFs for input  -------------- */
	if(pktsize<BUFFER_SIZE) pktsize = BUFFER_SIZE;
	if(pktnum<512) pktnum = 512;
	
	odp_pool_param_init(&params);
	params.pkt.seg_len    = pktsize;
	params.pkt.len        = pktsize;
	params.pkt.num        = pktnum;
	params.pkt.uarea_size = sizeof(fastnet_pkt_uarea_t);
	params.type           = ODP_POOL_PACKET;
	
	pool = odp_pool_create("fn_pktin",&params);
	if(pool == ODP_POOL_INVALID) return 0;
	
	/* ------------- Pool used by the net-stack for output  --------------*/
	
	if(!poutsize) poutsize = pktsize;
	if(!poutnum)  poutnum  = pktnum;
	
	odp_pool_param_init(&params);
	params.pkt.seg_len    = poutsize;
	params.pkt.len        = poutsize;
	params.pkt.num        = poutnum;
	params.pkt.uarea_size = sizeof(fastnet_pkt_uarea_t);
	params.type           = ODP_POOL_PACKET;
	
	pool = odp_pool_create("fn_pktout",&params);
	if(pool == ODP_POOL_INVALID) return 0;
	
	return 1;
}

int fastnet_niftable_prepare(nif_table_t* table,odp_instance_t instance) {
	table->workers = odp_cpumask_default_worker(&(table->cpumask), NET_MAXTHREAD);
	DEBUG( table->workers==0 );
	if(table->workers==0) return 0;
	table->instance = instance;
	return 1;
}

static inline
const char* str_join(const char* prefix,const char* postfix){
	return fastnet_dup_concat3(prefix,postfix,"");
}

nif_t* fastnet_openpktio(nif_table_t* table,const char* dev) {
	odp_pktio_t              pktio;
	odp_pktio_param_t        pktio_p;
	odp_pktin_queue_param_t  pktin_qp;
	odp_pktout_queue_param_t pktout_qp;
	nif_t*                   nif;
	odp_queue_t              loop;
	odp_queue_param_t        loop_p;
	odp_pool_t               pool;
	uint8_t mac_addr[6];
	int ret;
	
	pool = odp_pool_lookup("fn_pktin");
	if(pool == ODP_POOL_INVALID) return 0;
	
	if(table->max>=NET_NIFTAB_MAX_NIFS) return 0;
	nif = &(table->table[table->max]);
	nif->ipv4 = 0;
	
	odp_queue_param_init(&loop_p);
	loop_p.type        = ODP_QUEUE_TYPE_SCHED;
	loop_p.enq_mode    = ODP_QUEUE_OP_MT;
	loop = odp_queue_create(str_join(dev,"(loopback)"),&loop_p);
	DEBUG( loop==ODP_QUEUE_INVALID );
	if(loop==ODP_QUEUE_INVALID) return 0;
	nif->loopback = loop;
	
	/*
	 * Open network interface.
	 */
	odp_pktio_param_init(&pktio_p);
	pktio_p.in_mode = ODP_PKTIN_MODE_SCHED;
	pktio_p.out_mode = ODP_PKTOUT_MODE_QUEUE;
	pktio = odp_pktio_open(dev, pool, &pktio_p);
	DEBUG( pktio == ODP_PKTIO_INVALID );
	if (pktio == ODP_PKTIO_INVALID) goto error2;
	
	if(odp_pktio_mac_addr(pktio,mac_addr,sizeof mac_addr)<0){
		DBGPF("Device '%s' has no MAC address.\n",dev);
		goto error1;
	}
	DBGPF("Device '%s' MAC address is %02x:%02x:%02x:%02x:%02x:%02x\n",dev,
		(int)mac_addr[0],
		(int)mac_addr[1],
		(int)mac_addr[2],
		(int)mac_addr[3],
		(int)mac_addr[4],
		(int)mac_addr[5]
	);
	
	/*
	 * Store the mac address in the nif_t* structure.
	 */
	nif->hwaddr = fastnet_mac_to_int(mac_addr);
	
	/* Complete the NIF structure */
	nif->pktio = pktio;
	
	odp_queue_context_set(loop,nif,sizeof(*nif));
	
	/*
	 * Configure input-queues.
	 */
	#define CONFIGURE_PKTIN do{                               \
	odp_pktin_queue_param_init(&pktin_qp);                    \
	pktin_qp.queue_param.sched.sync  = ODP_SCHED_SYNC_ATOMIC; \
	pktin_qp.queue_param.context     = nif;                   \
	pktin_qp.queue_param.context_len = sizeof(*nif);          \
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

