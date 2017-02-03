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
#include <net/socket_tcp.h>
#include <net/std_lib.h>

static odp_pool_t objects;
static odp_pool_t hdrbufs;

enum {
	/*
	 * Ethernet header (14 bytes),
	 * VLAN tag(4 bytes),
	 * IPv6 header (40 bytes),
	 * TCP header(20 bytes)
	 */
	MAX_TCP_IP_ETH_HDR = 14 + 4 + 40 + 20,
	MAX_IP_ETH_HDR = 14 + 4 + 40,
};

void fastnet_tcp_initpool(){
	odp_pool_param_t epool;
	odp_pool_param_init(&epool);
	epool.type = ODP_POOL_BUFFER;
	epool.buf.num   = 512*1024;
	epool.buf.align = 8;
	epool.buf.size  = sizeof(fastnet_tcp_pcb_t);
	objects = odp_pool_create("tcp_pcb_pool",&epool);
	if(objects==ODP_POOL_INVALID) fastnet_abort();
	odp_pool_param_init(&epool);
	epool.type = ODP_POOL_PACKET;
	epool.pkt.num        = 512*1024;
	epool.pkt.len        = MAX_TCP_IP_ETH_HDR;
	epool.pkt.seg_len    = MAX_TCP_IP_ETH_HDR;
	epool.pkt.uarea_size = 0;
	hdrbufs = odp_pool_create("tcp_hdrbuf_pool",&epool);
	if(hdrbufs==ODP_POOL_INVALID) fastnet_abort();
}

fastnet_socket_t fastnet_tcp_allocate(){
	fastnet_tcp_pcb_t* ptr;
	fastnet_socket_t handle = odp_buffer_alloc(objects);	
	if(handle!=ODP_BUFFER_INVALID){
		ptr = odp_buffer_addr(handle);
		odp_ticketlock_init(&(ptr->lock));
		ptr->tcpiphdr.buf = ODP_PACKET_INVALID;
	}
	return handle;
}

fastnet_socket_t fastnet_tcp_allocate_with_hdr(){
	fastnet_tcp_pcb_t* ptr;
	fastnet_socket_t handle;
	odp_packet_t hbuf;
	
	hbuf = odp_packet_alloc(hdrbufs,MAX_TCP_IP_ETH_HDR);
	if(odp_unlikely(hbuf==ODP_PACKET_INVALID)) return ODP_BUFFER_INVALID;
	
	odp_packet_l2_offset_set(hbuf,MAX_IP_ETH_HDR);
	odp_packet_l3_offset_set(hbuf,MAX_IP_ETH_HDR);
	odp_packet_l4_offset_set(hbuf,MAX_IP_ETH_HDR);
	
	handle = odp_buffer_alloc(objects);	
	if(handle!=ODP_BUFFER_INVALID){
		ptr = odp_buffer_addr(handle);
		odp_ticketlock_init(&(ptr->lock));
		ptr->tcpiphdr.buf          = hbuf;
		ptr->tcpiphdr.eth_lifetime = 0;
	}
	return handle;
}

void fastnet_tcp_socket_finalize(fastnet_socket_t sock){
	fastnet_tcp_pcb_t* ptr;
	ptr = odp_buffer_addr(sock);
	if(ptr->tcpiphdr.buf!=ODP_PACKET_INVALID) odp_packet_free(ptr->tcpiphdr.buf);
}

