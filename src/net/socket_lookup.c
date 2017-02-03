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
#include <net/socket_key.h>
#include <net/std_lib.h>
#include <net/fnv1a.h>

/* Must be power of 2 */

#define HASHTAB_SZ           0x4000
#define HASHTAB_SZ_MOD(x)    x&0x3fff

#define HASHTAB_LOCKS        0x1000
#define HASHTAB_LOCKS_MOD(x) x&0xfff

static odp_shm_t  hashtab;

typedef struct {
	fastnet_socket_t   entries[HASHTAB_SZ];
	odp_spinlock_t     locks[HASHTAB_LOCKS];
} socket_table_t;

void fastnet_socket_init() {
	int i;
	hashtab = odp_shm_reserve("socket_table",sizeof(socket_table_t),8,0);
	if(hashtab==ODP_SHM_INVALID) fastnet_abort();
	socket_table_t* h = odp_shm_addr(hashtab);
	for(i=0;i<HASHTAB_SZ;++i)
		h->entries[i] = ODP_BUFFER_INVALID;
	for(i=0;i<HASHTAB_LOCKS;++i)
		odp_spinlock_init(&(h->locks[i]));
}

void fastnet_socket_put(fastnet_socket_t sock) {
	fastnet_sockstruct_t* sockinst;
	if(odp_unlikely(sock==ODP_BUFFER_INVALID)) return;
	sockinst = odp_buffer_addr(sock);
	
	/*
	 * Unlikely, because most decrements don't reach 0 (statistically).
	 */
	if(odp_unlikely(odp_atomic_fetch_dec_u32(&(sockinst->refc))==1)) {
		sockinst->finalizer(sock);
		odp_buffer_free(sock);
	}
}

void fastnet_socket_grab(fastnet_socket_t sock) {
	fastnet_sockstruct_t* sockinst;
	if(odp_unlikely(sock==ODP_BUFFER_INVALID)) return;
	sockinst = odp_buffer_addr(sock);
	odp_atomic_inc_u32(&(sockinst->refc));
}

static
uint32_t ht_hash(socket_key_t *key){
	return fastnet_fnv1a(fastnet_fnv1a_init(),(uint8_t*)key,sizeof(socket_key_t));
}

static
void fastnet_socket_finalizer_def(fastnet_socket_t sock){}

void fastnet_socket_construct(fastnet_socket_t sock,fastnet_socket_finalizer_t finalizer) {
	fastnet_sockstruct_t* sockinst;
	sockinst = odp_buffer_addr(sock);
	odp_atomic_init_u32(&(sockinst->refc),1);
	sockinst->is_ht = 0;
	sockinst->hash = ht_hash(&(sockinst->key));
	
	if(odp_likely(finalizer!=NULL))
		sockinst->finalizer = finalizer;
	else
		sockinst->finalizer = fastnet_socket_finalizer_def;
}

static
fastnet_socket_t ht_lookup(socket_key_t *key,uint32_t hash){
	fastnet_socket_t sock;
	fastnet_sockstruct_t* sockinst;
	uint32_t lock  = HASHTAB_LOCKS_MOD(hash);
	uint32_t index = HASHTAB_SZ_MOD(hash);
	
	socket_table_t* h = odp_shm_addr(hashtab);
	odp_spinlock_lock(&(h->locks[lock]));
	
	sock = h->entries[index];
	
	while(sock!=ODP_BUFFER_INVALID){
		sockinst = odp_buffer_addr(sock);
		if(sockinst->hash==hash){
			/* We found the socket. */
			if(odp_likely(fastnet_socket_key_eq(key,&(sockinst->key) ))){
				odp_atomic_inc_u32(&(sockinst->refc));
				
				/* True: sock != ODP_BUFFER_INVALID */
				break;
			}
		}
		sock = sockinst->next_ht;
	}
	/*
	 * Lemma:
	 *  IF( sock != ODP_BUFFER_INVALID ) THEN   odp_atomic_inc_u32()  was called.
	 *  IF( sock == ODP_BUFFER_INVALID ) THEN   odp_atomic_inc_u32()  was not called.
	 */
	
	odp_spinlock_unlock(&(h->locks[lock]));
	return sock;
}

static
fastnet_socket_t ht_insert(fastnet_socket_t sock,uint32_t hash){
	fastnet_sockstruct_t* sockinst;
	uint32_t lock  = HASHTAB_LOCKS_MOD(hash);
	uint32_t index = HASHTAB_SZ_MOD(hash);
	
	socket_table_t* h = odp_shm_addr(hashtab);
	odp_spinlock_lock(&(h->locks[lock]));
	
	sockinst = odp_buffer_addr(sock);
	if(!sockinst->is_ht) {
		sockinst->next_ht = h->entries[index];
		h->entries[index] = sock;
		odp_atomic_inc_u32(&(sockinst->refc));
		sockinst->is_ht = 0xffffff;
	}
	
	odp_spinlock_unlock(&(h->locks[lock]));
	return sock;
}

static
fastnet_socket_t ht_remove(fastnet_socket_t sock,uint32_t hash){
	fastnet_socket_t *elemptr;
	fastnet_sockstruct_t* sockinst;
	uint32_t lock  = HASHTAB_LOCKS_MOD(hash);
	uint32_t index = HASHTAB_SZ_MOD(hash);
	
	socket_table_t* h = odp_shm_addr(hashtab);
	odp_spinlock_lock(&(h->locks[lock]));
	
	sockinst = odp_buffer_addr(sock);
	if(sockinst->is_ht) {
	
		elemptr = &(h->entries[index]);
		while( (*elemptr) != ODP_BUFFER_INVALID ) {
			sockinst = odp_buffer_addr(*elemptr);
			if((*elemptr) != sock){
				elemptr = &(sockinst->next_ht);
				continue;
			}
			*elemptr = sockinst->next_ht;
			fastnet_socket_put(sock);
			break;
		}
		sockinst->is_ht = 0;
	}
	
	odp_spinlock_unlock(&(h->locks[lock]));
	return sock;
}

fastnet_socket_t fastnet_socket_lookup(socket_key_t *key) {
	fastnet_socket_t   sock;
	socket_key_t       listen_key;
	
	sock = ht_lookup(key,ht_hash(key));
	if(sock!=ODP_BUFFER_INVALID) return sock;
	
	/* Listening Socket. (no source address) */
	listen_key = *key;
	listen_key.src_ip = (ipv6_addr_t){.addr32={0,0,0,0}};
	listen_key.src_port = 0;
	listen_key.layer3_version &= 0xF;
	
	sock = ht_lookup(&listen_key,ht_hash(&listen_key));
	if(sock!=ODP_BUFFER_INVALID) return sock;
	
	/* IN_ANY */
	listen_key.dst_ip = (ipv6_addr_t){.addr32={0,0,0,0}};
	listen_key.layer3_version = 0;
	
	sock = ht_lookup(&listen_key,ht_hash(&listen_key));
	return sock;
}

void fastnet_socket_insert(fastnet_socket_t sock) {
	fastnet_sockstruct_t* sockinst;
	sockinst = odp_buffer_addr(sock);
	
	ht_insert(sock,sockinst->hash);
}

void fastnet_socket_remove(fastnet_socket_t sock) {
	fastnet_sockstruct_t* sockinst;
	sockinst = odp_buffer_addr(sock);
	
	ht_remove(sock,sockinst->hash);
}

