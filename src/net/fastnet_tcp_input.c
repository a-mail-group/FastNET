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
#include <net/_config.h>
#include <net/header/tcphdr.h>
#include <net/safe_packet.h>
#include <net/socket_tcp.h>
#include <net/fastnet_tcp.h>
#include <net/header/layer4.h>
#include <net/checksum.h>

netpp_retcode_t fastnet_tcp_input(odp_packet_t pkt) {
	socket_key_t key;
	fastnet_socket_t sock;
	
	/*
	 * Check checksum.
	 */
	if(odp_unlikely(fastnet_tcpudp_input_checksum(pkt,IP_PROTOCOL_TCP)!=0)) return NETPP_DROP;
	
	/*
	 * Socket Lookup.
	 */
	fastnet_socket_key_obtain(pkt,&key);
	key.layer4_version = IP_PROTOCOL_TCP;
	sock = fastnet_socket_lookup(&key);
	if(odp_likely(sock==ODP_BUFFER_INVALID)) return NETPP_DROP; /* XXX: should send RST. */
	
	return fastnet_tcp_process(pkt,&key,sock);
}


