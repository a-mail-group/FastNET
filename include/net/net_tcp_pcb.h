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
#include <net/header/iphdr.h>

/* XXX: may become obsolete. */

typedef struct ODP_PACKED
{
	fnet_ip_header_t ip;
	
} fastnet_tcpip_hdr_t;

struct fastnet_tcp_pcb {
	
};

