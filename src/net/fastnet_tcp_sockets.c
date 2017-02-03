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

void fastnet_tcp_initpool(){
	odp_pool_param_t epool;
	epool.type = ODP_POOL_BUFFER;
	epool.buf.num   = 512*1024;
	epool.buf.align = 8;
	epool.buf.size  = sizeof(fastnet_tcp_pcb_t);
	objects = odp_pool_create("tcp_pcb_pool",&epool);
	if(objects==ODP_POOL_INVALID) fastnet_abort();
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

