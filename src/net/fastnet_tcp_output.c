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
#include <net/config.h>
#include <net/header/tcphdr.h>
#include <net/header/layer4.h>
#include <net/socket_tcp.h>

static uint16_t wnd_to_16(uint32_t wnd){
	if(wnd<0xFFFF)return (uint16_t)wnd;
	return 0xFFFF;
}

netpp_retcode_t fastnet_tcp_output(odp_packet_t pkt,fastnet_socket_t sock,uint32_t seq_num,uint16_t flags){
	nif_t* nif;
	fastnet_tcp_pcb_t* pcb;
	odp_time_t now;
	uint32_t length;
	
	length = odp_packet_len(pkt);
	
	now = odp_time_global();
	
	pcb = odp_buffer_addr(sock);
	
	if(odp_unlikely(fastnet_tcp_add_header(pkt,pcb,now,&nif) )) return NETPP_DROP;
	
	fnet_tcp_parthdr_t thdr = {
		.sequence_number  = odp_cpu_to_be_32(seq_num),
		.ack_number       = odp_cpu_to_be_32(pcb->rcv.nxt),
		.hdrlength__flags = odp_cpu_to_be_16(0x5000|flags),
		.window           = odp_cpu_to_be_16(wnd_to_16(pcb->rcv.wnd)),
		.checksum         = 0,
		.urgent_ptr       = 0,
	};
	
	odp_packet_copy_from_mem(pkt,odp_packet_l4_offset(pkt)+3,sizeof(thdr),&thdr);
	
	return fastnet_tcp_sendout_ll(pkt,pcb,nif,length);
}

