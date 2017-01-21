/*
 *   Copyright 2016-2017 Simon Schmidt
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
#include <net/ipv6_mac_cache.h>
#include <net/fnv1a.h>
#include <net/std_lib.h>
#include <net/requirement.h>
#include <net/variables.h>

uint32_t fastnet_nd6_hard_timeout;   /* Default 1500 Seconds */
uint32_t fastnet_nd6_reachable_time; /* Default  30,000 milliseconds */
uint32_t fastnet_nd6_retrans_timer;  /* Default  1,000 milliseconds */

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
	STATE_INCOMPLETE,
	STATE_REACHABLE,
	STATE_STALE,
	STATE_DELAY,
	STATE_PROBE,
};



/* Must be power of 2 */

#define HASHTAB_SZ           0x1000
#define HASHTAB_SZ_MOD(x)    x&0xfff

#define HASHTAB_LOCKS        0x10
#define HASHTAB_LOCKS_MOD(x) x&0xf

typedef struct {
	ipv6_addr_t  ipaddr;
	nif_t*       nif;
	uint32_t     hash;
	union{
	uint64_t     hwaddr;
	odp_packet_t chain;
	};
	odp_time_t   tstamp;
	uint32_t     flags;
	
	odp_buffer_t next;
} ipv6_mac_entry_t;

enum {
	/*
	 * This flag indicates, that there is no Hardware-Address - this implies INCOMPLETE.
	 * This flag also indicates, that there may be a chain of unsendt packets.
	 */
	FLAGS_HAS_CHAIN = 1,    /* Implies INCOMPLETE. */
	FLAGS_HAS_STALE = 2,    /* True for { STALE, DELAY, PROBE } */
	FLAGS_HAS_DELAY = 4,    /* True for DELAY, optional for PROBE */
	FLAGS_HAS_PROBE = 8,    /* True for PROBE */
	FLAGS_IS_ROUTER = 0x10, /* IsRouter */
	
	FLAGS_IS_OVERRIDE = 0x100, /* For the Key: Override-flag has been set. */
	
	FLAGS_TYPE_NSOL = 0x1000, /* Set on key on Neighbor Solicitations. */
	FLAGS_TYPE_NADV = 0x2000, /* Set on key on Neighbor Advertisements. */
};

/*
 * Flag Table:
 *
 * Bits:
 *  - 0 : Bit is 0
 *  - 1 : Bit is 1
 *  - ? : Bit can be 0 or 1
 *
 * |1|2|4|8| RFC 4861  Neighbor state |
 * ------------------------------------
 * |1|?|?|?| INCOMPLETE               |
 * |0|0|0|0| REACHABLE                |
 * |0|1|0|0| STALE                    |
 * |0|1|1|0| DELAY                    |
 * |0|1|?|1| PROBE                    |
 */

typedef struct {
	odp_buffer_t   entries[HASHTAB_SZ];
	odp_spinlock_t locks[HASHTAB_LOCKS];
} i6m_ht_t;

static odp_pool_t entries;
static odp_shm_t  hashtab;

static
uint32_t ip_hash(nif_t* nif,ipv6_addr_t ipaddr){
	uint32_t hash = fastnet_fnv1a_init();
	hash = fastnet_fnv1a(hash,(uint8_t*)&nif,sizeof(nif));
	hash = fastnet_fnv1a(hash,(uint8_t*)&ipaddr,sizeof(ipaddr));
	return hash;
}

static
void ip_entry(nif_t* nif,ipv6_addr_t ipaddr, ipv6_mac_entry_t* __restrict__ entry){
	entry->ipaddr = ipaddr;
	entry->nif    = nif;
	entry->hash   = ip_hash(nif,ipaddr);
	entry->chain  = ODP_PACKET_INVALID;
	entry->tstamp = odp_time_local();
	entry->flags  = FLAGS_HAS_CHAIN;
	entry->next   = ODP_BUFFER_INVALID;
}
static int ip_entry_eq(ipv6_mac_entry_t* A,ipv6_mac_entry_t* B){
	return (A->nif == B->nif) && IP6ADDR_EQ(A->ipaddr,B->ipaddr);
}

static int ip_entry_timeout(odp_time_t diff){
	return diff.tv_sec > fastnet_nd6_hard_timeout;
}
static int ip_entry_timeout_soft(odp_time_t diff){
	//return diff.tv_sec > fastnet_arp_cache_timeout_soft;
	return 0;
}

static int ip_entry_get_state(ipv6_mac_entry_t* entry,odp_time_t now){
	uint32_t flags = entry->flags;
	odp_time_t diff;
	
	if(flags & FLAGS_HAS_CHAIN) return STATE_INCOMPLETE;
	if(!(flags & FLAGS_HAS_STALE)){
		diff = odp_time_diff(now,entry->tstamp);
		if(diff.tv_sec > fastnet_nd6_reachable_time) return STATE_STALE;
		return STATE_REACHABLE;
	}
	if(flags & FLAGS_HAS_PROBE) return STATE_PROBE;
	if(flags & FLAGS_HAS_DELAY) return STATE_DELAY;
	return STATE_STALE;
}

/*
 * Preconditions:
 *   if  key->flags & FLAGS_HAS_CHAIN   -> key->chain == ODP_PACKET_INVALID
 * Postconditions:
 *   RESULT must be one of { 0 ,  1 ,  2 , 3 }
 *   if  RESULT == 0  ->  entry->flags & FLAGS_HAS_CHAIN
 *   if  RESULT == 1  ->  Entry Updated
 *   if  RESULT == 2  ->  Key Updated; !(key->flags & FLAGS_HAS_CHAIN)
 *   if  RESULT == 3  ->  !( entry->flags & FLAGS_HAS_CHAIN )
 */
static int ip_entry_overwrite(ipv6_mac_entry_t* entry,ipv6_mac_entry_t* key) {
	uint32_t     flags;
	odp_packet_t chain;
	
	/*
	 * FLAGS_TYPE_NSOL is set in the key on every Neighbor Solicitation.
	 */
	if(key->flags & FLAGS_TYPE_NSOL){
		/*
		 * RFC-4861 7.2.3.  Receipt of Neighbor Solicitations
		 *
		 * If the Source Address is not the unspecified
		 * address and, on link layers that have addresses, the solicitation
		 * includes a Source Link-Layer Address option, then the recipient
		 * SHOULD create or update the Neighbor Cache entry for the IP Source
		 * Address of the solicitation.
		 *
		 *
		 * If an entry does not already exist, the
		 * node SHOULD create a new one and set its reachability state to STALE
		 * as specified in Section 7.3.3.
		 *
		 * If an entry already exists, and the
		 * cached link-layer address differs from the one in the received Source
		 * Link-Layer option, the cached address should be replaced by the
		 * received address, and the entry's reachability state MUST be set to
		 * STALE.
		 *
		 * If a Neighbor Cache entry already exists, its IsRouter flag MUST NOT
		 * be modified.
		 */
		if(entry->flags & FLAGS_HAS_CHAIN){
			flags = FLAGS_IS_ROUTER & entry->flags;
			chain = entry->chain;
			entry->hwaddr = key->hwaddr;
			entry->flags  = key->flags | flags;
			entry->tstamp = key->tstamp;
			key->chain = chain;
			key->flags |= FLAGS_HAS_CHAIN;
			return 1;
		}else if(entry->hwaddr != key->hwaddr){
			flags = FLAGS_IS_ROUTER & entry->flags;
			entry->hwaddr = key->hwaddr;
			entry->flags  = key->flags | flags;
			entry->tstamp = key->tstamp;
			return 1;
		}
		return 3;
	}
	
	/*
	 * FLAGS_TYPE_NADV is set in the key on every Neighbor Advertisement.
	 */
	if(key->flags & FLAGS_TYPE_NADV){
		/* 7.2.5.  Receipt of Neighbor Advertisements */
		
		/* If the entry is in the state INCOMPLETE... */
		if(entry->flags & FLAGS_HAS_CHAIN){
			chain = entry->chain;
			entry->hwaddr = key->hwaddr;
			entry->flags  = key->flags;
			entry->tstamp = key->tstamp;
			key->chain = chain;
			key->flags |= FLAGS_HAS_CHAIN;
			return 1;
		}
		/*
		 * If the target's Neighbor Cache entry is in any state other than
		 * INCOMPLETE when the advertisement is received, the following actions
		 * take place:
		 */
		
		/*
		 * I.
		 *   If the Override flag is clear and the supplied link-layer address
		 *   differs from that in the cache, then one of two actions takes
		 *   place:
		 */
		if(!(key->flags & FLAGS_IS_OVERRIDE)){
			if(entry->hwaddr == key->hwaddr) return 3;
			/*
			 * a. If the state of the entry is REACHABLE, set it to STALE, but
			 *    do not update the entry in any other way.
			 */
			if(ip_entry_get_state(entry,key->tstamp)==STATE_REACHABLE){
				entry->flags |= FLAGS_HAS_STALE;
			}
			/*
			 * b. Otherwise, the received advertisement should be ignored and
			 *    MUST NOT update the cache.
			 */
			return 1;
		}
		
		/*
		 * II.
		 *   If the Override flag is set, or the supplied link-layer address
		 *   is the same as that in the cache, or no Target Link-Layer Address
		 *   option was supplied, the received advertisement MUST update the
		 *   Neighbor Cache entry as follows:
		 */
		
		if( entry->hwaddr != key->hwaddr ){
			/*
			 * - The link-layer address in the Target Link-Layer Address option
			 *   MUST be inserted in the cache (if one is supplied and differs
			 *   from the already recorded address).
			 * - If the Solicited flag is set, the state of the entry MUST be
			 *   set to REACHABLE.  If the Solicited flag is zero and the link-
			 *   layer address was updated with a different address, the state
			 *   MUST be set to STALE.  Otherwise, the entry's state remains
			 *   unchanged.
			 * - The IsRouter flag in the cache entry MUST be set based on the
			 *   Router flag in the received advertisement.
			 */
			entry->hwaddr = key->hwaddr;
			entry->flags  = key->flags;
			entry->tstamp = key->tstamp;
		};
		entry->tstamp = entry->tstamp;
	}
	
	
	if(key->flags & FLAGS_HAS_CHAIN){
		if(!(entry->flags & FLAGS_HAS_CHAIN)){
			key->hwaddr = entry->hwaddr;
			key->flags  = entry->flags;
			key->tstamp = entry->tstamp;
			return 2;
		}
		return 0;
	}else if(entry->flags & FLAGS_HAS_CHAIN){
		chain = entry->chain;
		entry->hwaddr = key->hwaddr;
		entry->flags  = key->flags;
		entry->tstamp = key->tstamp;
		key->chain = chain;
		key->flags |= FLAGS_HAS_CHAIN;
		return 1;
	}else{
		entry->hwaddr = key->hwaddr;
		entry->flags  = key->flags;
		entry->tstamp = key->tstamp;
		return 1;
	}
}

void fastnet_initialize_ip6mac_cache(){
	int i;
	odp_pool_param_t epool;
	epool.type = ODP_EVENT_BUFFER;
	epool.buf.num   = 512*1024;
	epool.buf.size  = sizeof(ipv6_mac_entry_t);
	epool.buf.align = 8;
	entries = odp_pool_create("ipv6_mac_entries",&epool);
	if(entries==ODP_POOL_INVALID) fastnet_abort();
	hashtab = odp_shm_reserve("ipv6_mac_hashtab",sizeof(i6m_ht_t),8,0);
	if(hashtab==ODP_SHM_INVALID) fastnet_abort();
	i6m_ht_t* h = odp_shm_addr(hashtab);
	for(i=0;i<HASHTAB_SZ;++i)
		h->entries[i] = ODP_BUFFER_INVALID;
	for(i=0;i<HASHTAB_LOCKS;++i)
		odp_spinlock_init(&(h->locks[i]));
	fastnet_nd6_hard_timeout   = 1500;
	fastnet_nd6_reachable_time = 30000;
	fastnet_nd6_retrans_timer  = 1000;
	if(fastnet_arp_cache_timeout_soft>3) fastnet_arp_cache_timeout_soft-=3;
}

static void free_chain(odp_buffer_t buf){
	odp_packet_t pkt,nxt;
	ipv6_mac_entry_t* entry;
	
	entry = odp_buffer_addr(buf);
	if(!(entry->flags & FLAGS_HAS_CHAIN))return;
	
	pkt = entry->chain;
	while(pkt!=ODP_PACKET_INVALID){
		nxt = FASTNET_PACKET_UAREA(pkt)->next;
		odp_packet_free(pkt);
		pkt = nxt;
	}
}

/*
 * Return code:
 * -1 -> FAILED.
 *  0 -> packet consumed, if any.
 *  1 -> entry inserted or updated (or just found).
 *  2 -> key updated.
 *  3 -> no effect.
 */
static int
ipmac_lkup_or_insert(ipv6_mac_entry_t* key,odp_packet_t pkt,int create){
	int ret;
	uint32_t lock  = HASHTAB_LOCKS_MOD(key->hash);
	uint32_t index = HASHTAB_SZ_MOD(key->hash);
	odp_buffer_t* bufaddr;
	odp_buffer_t alloc;
	ipv6_mac_entry_t* entry;
	i6m_ht_t* h = odp_shm_addr(hashtab);
	odp_time_t diff;
	
	alloc = ODP_BUFFER_INVALID;
	
	odp_spinlock_lock(&(h->locks[lock]));
	bufaddr = &(h->entries[index]);
	
	ret = -1;
	
	while(*bufaddr != ODP_BUFFER_INVALID){
		entry = odp_buffer_addr(*bufaddr);
		if(ip_entry_eq(entry,key)){
			ret = ip_entry_overwrite(entry,key);
			
			/*
			 * If ret==0 and pkt is valid, then prepend it to the queue.
			 */
			if((pkt!=ODP_PACKET_INVALID) && ret==0){
				FASTNET_PACKET_UAREA(pkt)->next = entry->chain;
				entry->chain = pkt;
			}
			
			/* Since we found the entry, terminate the queue. */
			break;
		}
		diff = odp_time_diff(key->tstamp,entry->tstamp);
		
		/*
		 * If we found an outdated entry, we deal with it.
		 */
		if(ip_entry_timeout(diff)){
			if(alloc!=ODP_BUFFER_INVALID) odp_buffer_free(alloc);
			alloc = *bufaddr;
			*bufaddr = entry->next;
			free_chain(alloc);
			continue;
		}
		bufaddr = &entry->next;
	}
	
	if(odp_likely(create) && ret<0){
		if(alloc==ODP_BUFFER_INVALID) alloc = odp_buffer_alloc(entries);
		if(odp_unlikely(alloc==ODP_BUFFER_INVALID)) goto terminate;
		entry = odp_buffer_addr(alloc);
		*entry = *key;
		entry->next = *bufaddr;
		*bufaddr = alloc;
		if((pkt!=ODP_PACKET_INVALID) && (entry->flags & FLAGS_HAS_CHAIN)){
			FASTNET_PACKET_UAREA(pkt)->next = entry->chain;
			entry->chain = pkt;
			ret = 0;
		}else
			ret = 1;
	}else{
		if(alloc!=ODP_BUFFER_INVALID) odp_buffer_free(alloc);
	}
	
terminate:
	odp_spinlock_unlock(&(h->locks[lock]));
	return ret;
}

netpp_retcode_t fastnet_ipv6_mac_lookup(nif_t* nif,ipv6_addr_t ipaddr,uint64_t* hwaddr,int *sendnd6,odp_packet_t pkt){
	int ret;
	ipv6_mac_entry_t key;
	odp_time_t cur;
	ip_entry(nif,ipaddr,&key);
	cur = key.tstamp;
	
	ret = ipmac_lkup_or_insert(&key,pkt,1);
	*sendnd6 = 1;
	
	switch(ret){
	case -1: return NETPP_DROP;
	case 0:  return NETPP_CONSUMED;
	case 2:
		*sendnd6 = ip_entry_timeout_soft(odp_time_diff(cur,key.tstamp));
		if(hwaddr) *hwaddr = key.hwaddr;
		return NETPP_CONTINUE;
	default:return NETPP_DROP;
	};
	
	return NETPP_DROP;
}

odp_packet_t    fastnet_ipv6_mac_put(nif_t* nif,ipv6_addr_t ipaddr,uint64_t hwaddr,int create){
	ipv6_mac_entry_t key;
	ip_entry(nif,ipaddr,&key);
	key.flags = 0;
	key.hwaddr = hwaddr;
	
	if( ipmac_lkup_or_insert(&key,ODP_PACKET_INVALID,create) == 2 ){
		if(key.flags & FLAGS_HAS_CHAIN) return key.chain;
	}
	
	return ODP_PACKET_INVALID;
}

odp_packet_t    fastnet_ipv6_mac_nsol(nif_t* nif,ipv6_addr_t ipaddr,uint64_t hwaddr){
	ipv6_mac_entry_t key;
	ip_entry(nif,ipaddr,&key);
	key.flags = FLAGS_HAS_STALE | FLAGS_TYPE_NSOL;
	key.hwaddr = hwaddr;
	
	if( ipmac_lkup_or_insert(&key,ODP_PACKET_INVALID,1) == 2 ){
		if(key.flags & FLAGS_HAS_CHAIN) return key.chain;
	}
	
	return ODP_PACKET_INVALID;
}

odp_packet_t    fastnet_ipv6_mac_nadv(nif_t* nif,ipv6_addr_t ipaddr,uint64_t hwaddr,int flags){
	ipv6_mac_entry_t key;
	ip_entry(nif,ipaddr,&key);
	key.flags = FLAGS_TYPE_NADV;
	key.hwaddr = hwaddr;
	
	/*
	 * - If the advertisement's Solicited flag is set, the state of the
	 *   entry is set to REACHABLE; otherwise, it is set to STALE.
	 */
	if(!(flags & I6MC_NADV_SOLICITED)) key.flags |= FLAGS_HAS_STALE;
	
	/*
	 * - It sets the IsRouter flag in the cache entry based on the Router
	 *   flag in the received advertisement.
	 */
	if(flags & I6MC_NADV_ROUTER)   key.flags |= FLAGS_IS_ROUTER;
	
	if(flags & I6MC_NADV_OVERRIDE) key.flags |= FLAGS_IS_OVERRIDE;
	
	if( ipmac_lkup_or_insert(&key,ODP_PACKET_INVALID,0) == 2 ){
		if(key.flags & FLAGS_HAS_CHAIN) return key.chain;
	}
	
	return ODP_PACKET_INVALID;
}

