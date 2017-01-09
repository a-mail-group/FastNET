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
#include <stdio.h>
#include <stdlib.h>
#include <odp_api.h>
#include <net/niftable.h>
#include <net/ipv4.h>
#include <net/header/ip.h>

#define EXAMPLE_ABORT(...) do{ printf(__VA_ARGS__); abort(); }while(0)

#define PRINT_INT(expr) "\t" #expr " = %d\n"
static
netpp_retcode_t handle_packet(odp_packet_t pkt){
	printf("Packet{\n"
	"\thas L2=%d,L3=%d,L4=%d\n"
	"\tlayer3=%s%s%s\n"
	"\tlayer4=%s%s%s%s\n"
	"\toff L2=%u,L3=%u,L4=%u\n"
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
	
	,odp_packet_l2_offset(pkt)
	,odp_packet_l3_offset(pkt)
	,odp_packet_l4_offset(pkt)
	);
	return NETPP_DROP;
}

#define BUFFER_SIZE 1856
#define POOL_SIZE   (512*2048)

int main(){
	int i,p;

	/* ---------------------Packet IO Vars.----------------------- */
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_instance_t instance;
	//odph_odpthread_params_t thr_params;
	odp_pktio_t pktio;
	nif_table_t *table;
	nif_t *nif;
	struct ipv4_nif_struct* ipv4;
	ipv4 = calloc(sizeof(*ipv4),1);
	fastnet_ip_set(ipv4,ipv4_addr_init(10,0,3,9),ipv4_addr_init(0xff,0xff,0,0));
	
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
	
	table = calloc(sizeof(*table),1);
	
	//pktio = create_pktio("vmbridge0",pool);
	//pktio = create_pktio("eth0",pool);
	if(!fastnet_niftable_prepare(table,instance))
		EXAMPLE_ABORT("Error: nif-table init failed.\n");
	nif = fastnet_openpktio(table,"vmbridge0",pool);
	if(!nif)
		EXAMPLE_ABORT("Error: pktio create failed.\n");
	nif->ipv4 = ipv4;
	table->function = handle_packet;
	
	/* ---------------------Thread Code.----------------------- */
	
	fastnet_runthreads(table);
	
	odp_term_local();
	odp_term_global(instance);
	return 0;
}
