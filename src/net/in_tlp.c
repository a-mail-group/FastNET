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
#include <net/in_tlp.h>

#include <net/packet_input.h>
#include <net/header/layer4.h>

static
netpp_retcode_t def_protocol(odp_packet_t pkt){
	return NETPP_DROP;
}


struct fn_transport_layer_protocol fn_in_protocols[] = {
	{
		.in_protocol = IP_PROTOCOL_TCP,
		.in_hook = fastnet_tcp_input,
	},
	{
		.in_pt = INPT_DEFAULT,
		.in_hook = def_protocol,
	},
};
const unsigned int          fn_in_protocols_n = sizeof(fn_in_protocols)/sizeof(struct fn_transport_layer_protocol);

int fn_in4_protocol_idx[256];
int fn_in6_protocol_idx[256];

