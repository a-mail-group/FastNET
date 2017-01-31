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
#include <net/socket_key.h>

typedef struct {
	fastnet_sockstruct_t _head;
	/* ------------------------------------ */
	odp_ticketlock_t lock;
	
	uint8_t state;
	
	/*
	* RFC-793
	*
	*    Send Sequence Variables
	*
	*      SND.UNA - send unacknowledged
	*      SND.NXT - send next
	*      SND.WND - send window
	*      SND.UP  - send urgent pointer
	*      SND.WL1 - segment sequence number used for last window update
	*      SND.WL2 - segment acknowledgment number used for last window
	*                update
	*      ISS     - initial send sequence number
	*
	*    Receive Sequence Variables
	*
	*      RCV.NXT - receive next
	*      RCV.WND - receive window
	*      RCV.UP  - receive urgent pointer
	*      IRS     - initial receive sequence number
	*
	*/
	struct _fastnet_tcp_pcb_t_snd {
		uint32_t una; /* send unacknowledged */
		uint32_t nxt; /* send next */
		uint32_t wnd; /* send window */
		uint32_t up;  /* send urgent pointer */
		uint32_t wl1; /* segment sequence number used for last window update */
		uint32_t wl2; /* segment acknowledgment number used for last window update */
	} snd;
	struct _fastnet_tcp_pcb_t_rcv {
		uint32_t nxt; /* receive next */
		uint32_t wnd; /* receive window */
		uint32_t up;  /* receive urgent pointer */
	} rcv;
	uint32_t iss; /* initial send sequence number */
	uint32_t irs; /* initial receive sequence number */
	
} fastnet_tcp_pcb_t;


void fastnet_tcp_initpool();

fastnet_socket_t fastnet_tcp_allocate();

