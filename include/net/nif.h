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
#pragma once

#include <odp_api.h>
#include <net/header/ip.h>

#define NIFOFL_TCP_CKSUM  1
#define NIFOFL_UDP_CKSUM  2
#define NIFOFL_IP4_CKSUM  4


#define NET_NIF_MAX_QUEUE 128

struct ipv4_nif_struct;

typedef struct _nif_t {
	odp_pktio_t pktio;
	odp_queue_t output[NET_NIF_MAX_QUEUE];
	odp_queue_t loopback;
	
	int num_queues;
	
	uint32_t    offload_flags;
	
	uint64_t    hwaddr;
	struct ipv4_nif_struct *ipv4;
} nif_t;


