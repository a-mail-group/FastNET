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
#pragma once

#include <odp_api.h>

enum netpp_retcode {
	NETPP_CONTINUE = 0, /* Packet (not) modified. Continue Processing! */
	NETPP_CONSUMED,     /* Packet consumed. Don't touch it. */
	NETPP_DROP,         /* Packet (not) modified. Drop packet! */
};

typedef enum netpp_retcode netpp_retcode_t;

typedef netpp_retcode_t (*netpp_cb_t)(odp_packet_t pkt);


