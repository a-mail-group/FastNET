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
#include <net/types.h>
#include <odp_api.h>

typedef netpp_retcode_t (*netpp_cb6_t)(odp_packet_t pkt,int* nxt, int idx);

typedef void (*fn_tlpinit_t)();

enum {
	INPT_PROTOCOL=0, /* A transport protocol for IPv4 and IPv6. */
	INPT_DEFAULT,    /* Default handler, if no other Protocol handler is defined. */
	INPT_DEFAULT6,   /* Default handler, if no other Protocol handler is defined (IPv6). */
	INPT_IPV6_ONLY,  /* A transport protocol for IPv6 only. */
};

struct fn_transport_layer_protocol {
	uint8_t      in_protocol;
	uint8_t      in_pt;
	netpp_cb_t   in_hook;
	netpp_cb6_t  in6_hook;
	fn_tlpinit_t tlp_init;
};

extern struct fn_transport_layer_protocol fn_in_protocols[];
extern const unsigned int                 fn_in_protocols_n;

extern int fn_in4_protocol_idx[];
extern int fn_in6_protocol_idx[];

