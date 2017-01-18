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
#include <net/in_tlp.h>
#include <net/niftable.h>
#include <net/ipv4.h>
#include <net/ipv6.h>
#include <net/packet_input.h>
#include <net/header/ip.h>
#include <net/requirement.h>

#include <net/header/iphdr.h>
#include <net/header/ip6hdr.h>

#define EXAMPLE_ABORT(...) do{ printf(__VA_ARGS__); abort(); }while(0)

#define PRINT_INT(expr) "\t" #expr " = %d\n"
static
netpp_retcode_t handle_packet(odp_packet_t pkt){
	fnet_ip_header_t* ip;
	fnet_ip6_header_t* ip6;
	uint32_t len,l3p,plen;
	
	#if 0
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
	#endif
	
	/*
	 * len seems to equal plen, when I tested it.
	 *
	 * It seems to me, the packet Ethernet frame comes without the trailing CRC32 checksum.
	 * Hmmmmmm.... Maybe, it is unecessary to append one?
	 */
	printf("NIF = %p\n",odp_packet_user_ptr(pkt));
	if(odp_packet_has_ipv4(pkt)){
		ip = odp_packet_l3_ptr(pkt,NULL);
		len = odp_be_to_cpu_16(ip->total_length);
		l3p = odp_packet_l3_offset(pkt);
		plen = odp_packet_len(pkt)-l3p;
		
		printf("IP4:len = %d; plen = %d\n",len,plen);
	}else if(odp_packet_has_ipv6(pkt)){
		ip6 = odp_packet_l3_ptr(pkt,NULL);
		len = odp_be_to_cpu_16(ip6->length) + sizeof(fnet_ip6_header_t);
		l3p = odp_packet_l3_offset(pkt);
		plen = odp_packet_len(pkt)-l3p;
		
		printf("IP6:len = %d; plen = %d\n",len,plen);
	};
	
	
	return NETPP_DROP;
}

#define BUFFER_SIZE 1856
#define POOL_SIZE   (512*2048)

static
void test_arpcache(){
	int i;
	int sendarp;
	uint64_t hwaddr;
	ipv4_addr_t addr;
	for(i=1;i<16;++i){
		addr = ipv4_addr_init(192,168,99,i);
		hwaddr = addr;
		printf("I  %08x -> %08x\n",(int)addr,(int)hwaddr);
		fastnet_ipv4_mac_put(NULL,addr,hwaddr,1);
	}
	
	for(i=1;i<32;++i){
		addr = ipv4_addr_init(192,168,99,i);
		switch(fastnet_ipv4_mac_lookup(NULL,addr,&hwaddr,&sendarp,ODP_PACKET_INVALID)) {
		case NETPP_CONTINUE:
			printf(" O %08x -> %08x\n",(int)addr,(int)hwaddr);
			break;
		case NETPP_DROP:
			printf(" O %08x -> FAIL\n",(int)addr);
			break;
		default:
			printf(" O %08x -> NOT_FOUND\n",(int)addr);
			break;
		}
	}
}

int main(){
	int i,p;

	/* ---------------------Packet IO Vars.----------------------- */
	odp_pool_param_t params;
	odp_instance_t instance;
	//odph_odpthread_params_t thr_params;
	odp_pktio_t pktio;
	nif_table_t *table;
	nif_t *nif;
	struct ipv4_nif_struct* ipv4;
	struct ipv6_nif_struct* ipv6;
	ipv4 = calloc(sizeof(*ipv4),1);
	ipv6 = calloc(sizeof(*ipv6),1);
	fastnet_ip_set(ipv4,ipv4_addr_init(192,168,99,109),ipv4_addr_init(0xff,0xff,0,0));
	// Ping me: 192.168.99.109
	
	/* ---------------------Packet IO Code.----------------------- */
	odp_init_global(&instance, NULL, NULL);
	odp_init_local(instance, ODP_THREAD_CONTROL);
	
	table = calloc(sizeof(*table),1);
	
	//pktio = create_pktio("vmbridge0",pool);
	//pktio = create_pktio("eth0",pool);
	/*
	"vmbridge0"
	"eth0"
	"tap:tap1"
	*/
	if(!fastnet_pools_init(0,0,0,0))
		EXAMPLE_ABORT("Error: allocating pools.\n");
	fastnet_tlp_init();
	if(!fastnet_niftable_prepare(table,instance))
		EXAMPLE_ABORT("Error: nif-table init failed.\n");
	nif = fastnet_openpktio(table,"tap:tap1");
	if(!nif)
		EXAMPLE_ABORT("Error: pktio create failed.\n");
	nif->ipv4 = ipv4;
	nif->ipv6 = ipv6;
	
	//table->function = handle_packet;
	table->function = fastnet_classified_input;
	
	/* ---------------------Thread Code.----------------------- */
	
	fastnet_runthreads(table);
	
	odp_term_local();
	odp_term_global(instance);
	return 0;
}
