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
#include <net/header/ip6.h>
#include <net/nif.h>

typedef odp_buffer_t nd6_nce_handle_t;

/*
 * Neighbor-Cache Entry.
 *
 * RFC-4861 5.1.  Conceptual Data Structures
 *   Neighbor Cache (one for each interface)
 *      A set of entries about individual neighbors to
 *      which traffic has been sent recently.  Entries are
 *      keyed on the neighbor's on-link unicast IP address
 *      and contain such information as its link-layer
 *      address, a flag indicating whether the neighbor is
 *      a router or a host (called IsRouter in this
 *      document), a pointer to any queued packets waiting
 *      for address resolution to complete, etc.  A
 *      Neighbor Cache entry also contains information used
 *      by the Neighbor Unreachability Detection algorithm,
 *      including the reachability state, the number of
 *      unanswered probes, and the time the next Neighbor
 *      Unreachability Detection event is scheduled to take
 *      place.
 */
typedef struct{
	nd6_nce_handle_t next_hashtab; /* Next entry in HT-Bucket. */
	nd6_nce_handle_t next_agelist; /* Next entry in Age-List. */
	nd6_nce_handle_t next_router;  /* Next entry in Router-List. */
	
	uint8_t   in_hashtab;
	uint8_t   in_agelist;
	uint8_t   in_router;
	
	/* PRIMARY KEY (*/
	nif_t*           nif;    /* network interface */
	ipv6_addr_t      ipaddr; /* neighbor's on-link unicast IP */
	/* ) */
	uint32_t         key_hash;
	
	uint64_t         hwaddr;
	
	odp_time_t       state_tstamp; /* Last State-Change. */
	uint8_t          state;
	uint8_t          is_router;
	
	odp_time_t       router_tstamp;   /* Router's timestamp. */
	uint16_t         router_lifetime; /* Router's lifetime in seconds. */
	
	odp_packet_t     chain;
	
	odp_atomic_u32_t refc;
} nd6_nce_t;


/*
 * RFC 4861:
 * 5.1.  Conceptual Data Structures
 *
 *    INCOMPLETE  Address resolution is in progress and the link-layer
 *                address of the neighbor has not yet been determined.
 *
 *    REACHABLE   Roughly speaking, the neighbor is known to have been
 *                reachable recently (within tens of seconds ago).
 *
 *    STALE       The neighbor is no longer known to be reachable but
 *                until traffic is sent to the neighbor, no attempt
 *                should be made to verify its reachability.
 *
 *    DELAY       The neighbor is no longer known to be reachable, and
 *                traffic has recently been sent to the neighbor.
 *                Rather than probe the neighbor immediately, however,
 *                delay sending probes for a short while in order to
 *                give upper-layer protocols a chance to provide
 *                reachability confirmation.
 *
 *    PROBE       The neighbor is no longer known to be reachable, and
 *                unicast Neighbor Solicitation probes are being sent to
 *                verify reachability.
 *
 */
enum {
	/*
	 * This states indicates, that the Entry is a 'phantom-Entry' which
	 * means, that it behaves like a non-existing Entry in the context of
	 * the means of RFC-4861 (or any other specification).
	 *
	 * Phantom-Entries are used, for example, to represent entries in the
	 * Default Router List, for which no Neigbor-Cache-Entry had been
	 * created.
	 *
	 * In order to create an RFC-4861-compliant Entry over an existing
	 * Phantom-Entry, the code MUST alter it's state into one of the states
	 * as defined by RFC 4861.
	 * Code creating Entries by eighter allocating new Entries or overwriting
	 * Phantom-Entries MUST NOT differ it's behavoir depending on wether a
	 * Phantom-Entry exists or not.
	 */
	ND6_NC__PHANTOM_,
	
	/* RFC 4861 NC-Entry states */
	ND6_NC_INCOMPLETE,
	ND6_NC_REACHABLE,
	ND6_NC_STALE,
	ND6_NC_DELAY,
	ND6_NC_PROBE,
};

void fastnet_nd6_cache_init();

nd6_nce_handle_t fastnet_nd6_nce_alloc();

void fastnet_nd6_nce_grab(nd6_nce_handle_t handle);

void fastnet_nd6_nce_put(nd6_nce_handle_t handle);


void fastnet_nd6_nce_lock_key(nif_t* nif, ipv6_addr_t addr);

void fastnet_nd6_nce_unlock_key(nif_t* nif, ipv6_addr_t addr);

/*
 * like:
 *    nd6_nce_t* ptr = odp_buffer_addr(handle);
 *    fastnet_nd6_nce_lock_key( ptr->nif, ptr->ipaddr);
 * but faster.
 */
void fastnet_nd6_nce_lock(nd6_nce_handle_t handle);

/*
 * like:
 *    nd6_nce_t* ptr = odp_buffer_addr(handle);
 *    fastnet_nd6_nce_unlock_key( ptr->nif, ptr->ipaddr);
 * but faster.
 */
void fastnet_nd6_nce_unlock(nd6_nce_handle_t handle);


void fastnet_nd6_nce_hashit(nd6_nce_handle_t handle);

void fastnet_nd6_nce_ht_enter(nd6_nce_handle_t handle);

void fastnet_nd6_nce_ht_leave(nd6_nce_handle_t handle);

nd6_nce_handle_t fastnet_nd6_nce_find(nif_t* nif, ipv6_addr_t addr);

/* Router-List stuff. */
void fastnet_nd6_nce_rl_enter(nd6_nce_handle_t handle);

void fastnet_nd6_nce_rl_leave(nd6_nce_handle_t handle);

