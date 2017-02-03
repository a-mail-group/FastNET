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
#include <net/nif.h>
#include <net/types.h>
#include <net/header/ip6.h>

typedef struct {
	ipv6_addr_t src_ip, dst_ip;
	uint16_t src_port,dst_port;
	nif_t * nif;
	uint8_t layer3_version; /* 0x44 = IPv4; 0x66 = IPv6 */
	uint8_t layer4_version; /* next_header or protocol-id */
} socket_key_t;

typedef odp_buffer_t fastnet_socket_t;

typedef void (*fastnet_socket_finalizer_t)(fastnet_socket_t sock);

typedef struct{
	fastnet_socket_t next_ht;
	odp_atomic_u32_t refc;
	uint32_t         is_ht;
	
	socket_key_t key;
	uint32_t     hash;
	uint32_t     type_tag;
	
	/* Finalizer */
	fastnet_socket_finalizer_t finalizer;
} fastnet_sockstruct_t;

/*
 * Obtains the IP-level fields of the socket key.
 *
 * The fields src_port, dst_port and layer4_version are left to be filled by the callee.
 */
netpp_retcode_t fastnet_socket_key_obtain_ip(odp_packet_t pkt, socket_key_t *key);

/*
 * Obtains the IP-level fields of the socket key, and the ports.
 *
 * The field layer4_version is left to be filled by the callee.
 */
netpp_retcode_t fastnet_socket_key_obtain(odp_packet_t pkt, socket_key_t *key);

/*
 * Compares two socket keys.
 */
int fastnet_socket_key_eq(socket_key_t *a,socket_key_t *b);

/*
 * Initializes the socket table.
 */
void fastnet_socket_init();

/*
 * Decrements the refcount of an socket.
 */
void fastnet_socket_put(fastnet_socket_t sock);

/*
 * Increments the refcount of an socket.
 */
void fastnet_socket_grab(fastnet_socket_t sock);

/*
 * Initializes the Header.
 */
void fastnet_socket_construct(fastnet_socket_t sock,fastnet_socket_finalizer_t finalizer);

/*
 * Lookup socket.
 */
fastnet_socket_t fastnet_socket_lookup(socket_key_t *key);

/*
 * Insert socket.
 */
void fastnet_socket_insert(fastnet_socket_t sock);

/*
 * Remove socket.
 */
void fastnet_socket_remove(fastnet_socket_t sock);

