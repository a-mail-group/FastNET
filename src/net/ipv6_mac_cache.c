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
#include <stdlib.h>
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
	FLAGS_HAS_CHAIN = 1, /* Implies INCOMPLETE. */
	FLAGS_HAS_STALE = 2, /* True for { STALE, DELAY, PROBE } */
	FLAGS_HAS_DELAY = 4, /* True for DELAY, optional for PROBE */
	FLAGS_HAS_PROBE = 8, /* True for PROBE */
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
	hash = fastnet_fnv1a(hash,&nif,sizeof(nif));
	hash = fastnet_fnv1a(hash,&ipaddr,sizeof(ipaddr));
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

/*
 * Preconditions:
 *   if  key->flags & FLAGS_HAS_CHAIN   -> key->chain == ODP_PACKET_INVALID
 * Postconditions:
 *   RESULT must be one of {  0 ,  1 ,  2  }
 *   if  RESULT == 0  ->  entry->flags & FLAGS_HAS_CHAIN
 *   if  RESULT == 1  ->  Entry Updated
 *   if  RESULT == 2  ->  Key Updated; !(key->flags & FLAGS_HAS_CHAIN)
 */
static int ip_entry_overwrite(ipv6_mac_entry_t* entry,ipv6_mac_entry_t* key) {
	uint32_t     flags;
	odp_packet_t chain;
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
	if(entries==ODP_POOL_INVALID) abort();
	hashtab = odp_shm_reserve("ipv6_mac_hashtab",sizeof(i6m_ht_t),8,0);
	if(hashtab==ODP_SHM_INVALID) abort();
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

netpp_retcode_t fastnet_ipv6_mac_lookup(nif_t* nif,ipv6_addr_t ipaddr,uint64_t* hwaddr,int *sendarp,odp_packet_t pkt){
	int ret;
	ipv6_mac_entry_t key;
	odp_time_t cur;
	ip_entry(nif,ipaddr,&key);
	cur = key.tstamp;
	
	ret = ipmac_lkup_or_insert(&key,pkt,1);
	*sendarp = 1;
	
	switch(ret){
	case -1: return NETPP_DROP;
	case 0:  return NETPP_CONSUMED;
	case 2:
		*sendarp = ip_entry_timeout_soft(odp_time_diff(cur,key.tstamp));
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

