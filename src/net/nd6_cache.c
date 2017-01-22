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
#include <net/nd6_cache.h>
#include <net/fnv1a.h>
#include <net/std_lib.h>
#include <net/_config.h>

/* Must be power of 2 */

#define HASHTAB_SZ           0x1000
#define HASHTAB_SZ_MOD(x)    x&0xfff

#define HASHTAB_LOCKS        0x10
#define HASHTAB_LOCKS_MOD(x) x&0xf


typedef struct{
	nd6_nce_handle_t buckets[HASHTAB_SZ];
	odp_spinlock_t   bucket_locks  [HASHTAB_LOCKS];
	odp_spinlock_t   instance_locks[HASHTAB_LOCKS];
} neighbor_cache_t;

typedef struct{
	nd6_nce_handle_t first_router;
	odp_spinlock_t   list_lock;
} router_list_t;

static void
nc_init(neighbor_cache_t* nc){
	int i;
	for(i=0;i<HASHTAB_SZ;++i)
		nc->buckets[i] = ODP_BUFFER_INVALID;
	for(i=0;i<HASHTAB_LOCKS;++i){
		odp_spinlock_init(&(nc->bucket_locks[i]));
		odp_spinlock_init(&(nc->instance_locks[i]));
	}
}

static void
rl_init(router_list_t* rl){
	rl->first_router = ODP_BUFFER_INVALID;
	odp_spinlock_init(&(rl->list_lock));
}

typedef struct{
	neighbor_cache_t  neighbor;
	router_list_t     router;
} nd6_cache_t;

static
uint32_t ip6_hash(nif_t* nif,ipv6_addr_t ipaddr){
	uint32_t hash = fastnet_fnv1a_init();
	hash = fastnet_fnv1a(hash,(uint8_t*)&nif,sizeof(nif));
	hash = fastnet_fnv1a(hash,(uint8_t*)&ipaddr,sizeof(ipaddr));
	return hash;
}

static odp_pool_t nc_entries;
static odp_shm_t  hashtab;

void fastnet_nd6_cache_init(){
	int i;
	nd6_cache_t* ci;
	
	odp_pool_param_t epool;
	epool.type = ODP_EVENT_BUFFER;
	epool.buf.num   = 512*1024;
	epool.buf.align = 8;
	
	epool.buf.size  = sizeof(neighbor_cache_t);
	nc_entries = odp_pool_create("nd6_nc_entries",&epool);
	if(nc_entries==ODP_POOL_INVALID) fastnet_abort();
	
	
	hashtab = odp_shm_reserve("nd6_hashtable",sizeof(nd6_cache_t),8,0);
	if(hashtab==ODP_SHM_INVALID) fastnet_abort();
	ci = odp_shm_addr(hashtab);
	nc_init(&(ci->neighbor));
	rl_init(&(ci->router));
}

/* ----------------------- Neighbor Cache Entries --------------------------- */


nd6_nce_handle_t fastnet_nd6_nce_alloc(){
	nd6_nce_t *ptr;
	nd6_nce_handle_t handle = odp_buffer_alloc(nc_entries);
	if(handle!=ODP_BUFFER_INVALID){
		ptr = odp_buffer_addr(handle);
		odp_atomic_init_u32(&(ptr->refc),1);
		ptr->in_hashtab = 0;
		ptr->in_agelist = 0;
		ptr->in_router = 0;
		ptr->chain = ODP_PACKET_INVALID;
	}
	return handle;
}

void fastnet_nd6_nce_grab(nd6_nce_handle_t handle){
	nd6_nce_t *ptr;
	if(odp_unlikely(handle==ODP_BUFFER_INVALID)) return;
	ptr = odp_buffer_addr(handle);
	
	odp_atomic_inc_u32(&(ptr->refc));
}

void fastnet_nd6_nce_put(nd6_nce_handle_t handle){
	nd6_nce_t *ptr;
	if(odp_unlikely(handle==ODP_BUFFER_INVALID)) return;
	ptr = odp_buffer_addr(handle);
	
	/*
	 * Unlikely, because most decrements don't reach 0 (statistically).
	 */
	if(odp_unlikely(odp_atomic_fetch_dec_u32(&(ptr->refc))==1)) odp_buffer_free(handle);
}

void fastnet_nd6_nce_lock_key(nif_t* nif, ipv6_addr_t addr){
	uint32_t     hash;
	unsigned     lockno;
	nd6_cache_t *ci;
	
	ci = odp_shm_addr(hashtab);
	
	hash = ip6_hash(nif,addr);
	
	lockno = HASHTAB_LOCKS_MOD(hash);
	
	odp_spinlock_lock(&(ci->neighbor.instance_locks[lockno]));
}

void fastnet_nd6_nce_unlock_key(nif_t* nif, ipv6_addr_t addr){
	uint32_t     hash;
	unsigned     lockno;
	nd6_cache_t *ci;
	
	ci = odp_shm_addr(hashtab);
	
	hash = ip6_hash(nif,addr);
	
	lockno = HASHTAB_LOCKS_MOD(hash);
	
	odp_spinlock_unlock(&(ci->neighbor.instance_locks[lockno]));
}

void fastnet_nd6_nce_lock(nd6_nce_handle_t handle){
	nd6_nce_t *ptr;
	nd6_cache_t *ci;
	unsigned   lockno;
	if(odp_unlikely(handle==ODP_BUFFER_INVALID)) return;
	ptr = odp_buffer_addr(handle);
	lockno = HASHTAB_LOCKS_MOD(ptr->key_hash);
	
	ci = odp_shm_addr(hashtab);
	
	odp_spinlock_lock(&(ci->neighbor.instance_locks[lockno]));
}

void fastnet_nd6_nce_unlock(nd6_nce_handle_t handle){
	nd6_nce_t *ptr;
	nd6_cache_t *ci;
	unsigned   lockno;
	if(odp_unlikely(handle==ODP_BUFFER_INVALID)) return;
	ptr = odp_buffer_addr(handle);
	lockno = HASHTAB_LOCKS_MOD(ptr->key_hash);
	
	ci = odp_shm_addr(hashtab);
	odp_spinlock_unlock(&(ci->neighbor.instance_locks[lockno]));
}

void fastnet_nd6_nce_hashit(nd6_nce_handle_t handle){
	nd6_nce_t *ptr;
	if(odp_unlikely(handle==ODP_BUFFER_INVALID)) return;
	ptr = odp_buffer_addr(handle);
	ptr->key_hash = ip6_hash(ptr->nif,ptr->ipaddr);
}

void fastnet_nd6_nce_ht_enter(nd6_nce_handle_t handle){
	nd6_nce_t *ptr;
	nd6_cache_t *ci;
	unsigned   lockno,hashno;
	if(odp_unlikely(handle==ODP_BUFFER_INVALID)) return;
	ptr = odp_buffer_addr(handle);
	lockno = HASHTAB_LOCKS_MOD(ptr->key_hash);
	hashno = HASHTAB_SZ_MOD(ptr->key_hash);
	
	ci = odp_shm_addr(hashtab);
	
	odp_atomic_inc_u32(&(ptr->refc));
	
	odp_spinlock_lock(&(ci->neighbor.bucket_locks[lockno]));
	
	if(odp_unlikely(ptr->in_hashtab)) goto terminate;
	
	ptr->next_hashtab = ci->neighbor.buckets[hashno];
	ci->neighbor.buckets[hashno] = ptr->next_hashtab;
	
	ptr->in_hashtab = 0xff;
	
	terminate:
	odp_spinlock_unlock(&(ci->neighbor.bucket_locks[lockno]));
}

void fastnet_nd6_nce_ht_leave(nd6_nce_handle_t handle){
	nd6_nce_t *ptr;
	nd6_cache_t *ci;
	nd6_nce_handle_t *bp;
	unsigned   lockno,hashno;
	if(odp_unlikely(handle==ODP_BUFFER_INVALID)) return;
	ptr = odp_buffer_addr(handle);
	lockno = HASHTAB_LOCKS_MOD(ptr->key_hash);
	hashno = HASHTAB_SZ_MOD(ptr->key_hash);
	
	ci = odp_shm_addr(hashtab);
	
	odp_spinlock_lock(&(ci->neighbor.bucket_locks[lockno]));
	
	if(odp_unlikely(!(ptr->in_hashtab))) goto terminate;
	
	ptr->in_hashtab = 0;
	
	bp = &(ci->neighbor.buckets[hashno]);
	while(*bp != handle){
		if(odp_unlikely(*bp==ODP_BUFFER_INVALID)) goto terminate;
		bp = &(((nd6_nce_t*)odp_buffer_addr(*bp))->next_hashtab);
	}
	NET_ASSERT( *bp == handle );
	*bp = ptr->next_hashtab;
	fastnet_nd6_nce_put(handle);
	
	terminate:
	odp_spinlock_unlock(&(ci->neighbor.bucket_locks[lockno]));
}

nd6_nce_handle_t fastnet_nd6_nce_find(nif_t* nif, ipv6_addr_t addr){
	nd6_nce_t *ptr;
	nd6_cache_t *ci;
	nd6_nce_handle_t handle;
	unsigned   lockno,hashno;
	uint32_t   hash;
	
	ci = odp_shm_addr(hashtab);
	
	hash = ip6_hash(nif,addr);
	
	lockno = HASHTAB_LOCKS_MOD(hash);
	hashno = HASHTAB_SZ_MOD(hash);
	
	odp_spinlock_lock(&(ci->neighbor.bucket_locks[lockno]));
	
	handle = ci->neighbor.buckets[hashno];
	
	while(handle != ODP_BUFFER_INVALID){
		ptr = odp_buffer_addr(handle);
		if(odp_unlikely(ptr->key_hash == hash))
		if(odp_likely(ptr->nif == nif))
		if(odp_likely(IP6ADDR_EQ(ptr->ipaddr,addr))) break;
		
		handle = ptr->next_hashtab;
	}
	
	if(odp_unlikely(handle == ODP_BUFFER_INVALID)){
		odp_spinlock_unlock(&(ci->neighbor.bucket_locks[lockno]));
		return ODP_BUFFER_INVALID;
	}
	
	odp_atomic_inc_u32(&(ptr->refc));
	odp_spinlock_unlock(&(ci->neighbor.bucket_locks[lockno]));
	
	return handle;
}

/* ----------------------- Default Router List --------------------------- */

void fastnet_nd6_nce_rl_enter(nd6_nce_handle_t handle){
	nd6_nce_t *ptr;
	nd6_cache_t *ci;
	if(odp_unlikely(handle==ODP_BUFFER_INVALID)) return;
	ptr = odp_buffer_addr(handle);
	
	ci = odp_shm_addr(hashtab);
	
	odp_spinlock_lock(&(ci->router.list_lock));
	
	if(odp_unlikely(ptr->in_hashtab)) goto terminate;
	
	ptr->next_router = ci->router.first_router;
	ci->router.first_router = ptr->next_router;
	
	ptr->in_hashtab = 0xff;
	
	terminate:
	odp_spinlock_unlock(&(ci->router.list_lock));
}

void fastnet_nd6_nce_rl_leave(nd6_nce_handle_t handle){
	nd6_nce_t *ptr;
	nd6_cache_t *ci;
	nd6_nce_handle_t *bp;
	if(odp_unlikely(handle==ODP_BUFFER_INVALID)) return;
	ptr = odp_buffer_addr(handle);
	
	ci = odp_shm_addr(hashtab);
	
	odp_spinlock_lock(&(ci->router.list_lock));
	
	if(odp_unlikely(!(ptr->in_hashtab))) goto terminate;
	ptr->in_hashtab = 0;
	
	bp = &(ci->router.first_router);
	while(*bp != handle){
		if(odp_unlikely(*bp==ODP_BUFFER_INVALID)) goto terminate;
		bp = &(((nd6_nce_t*)odp_buffer_addr(*bp))->next_router);
	}
	NET_ASSERT( *bp == handle );
	*bp = ptr->next_router;
	fastnet_nd6_nce_put(handle);
	
	terminate:
	odp_spinlock_unlock(&(ci->router.list_lock));
}

