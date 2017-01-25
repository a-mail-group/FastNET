/*
 *   Copyright 2016-2017 Simon Schmidt
 *   Copyright 2011-2016 by Andrey Butok. FNET Community.
 *   Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
 *   Copyright 2003 by Andrey Butok. Motorola SPS.
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
#include <net/nif.h>
#include <net/header/ip6.h>

#define IPV6_DEFAULT_PREFIX 64

#define IPV6_NIF_ADDR_MAX     8
#define IPV6_NIF_MULTCAST_MAX 20

enum
{
	FASTNET_IP6_ADDR_TYPE_MANUAL = 0,            /* The address is set manually.*/
	FASTNET_IP6_ADDR_TYPE_AUTOCONFIGURABLE = 1,  /* The address is set using "Auto-IP" link-local autoconfiguration. */
	FASTNET_IP6_ADDR_TYPE_DHCP = 2               /* The address is set using DHCP. */
};

enum
{
	FASTNET_IP6_ADDR_TENTATIVE = 0, /* Tentative address*/
	FASTNET_IP6_ADDR_PREFERED  = 1, /* Tentative address*/
};

typedef struct
{
	ipv6_addr_t   address;                   /* IPv6 address.*/
	ipv6_addr_t   solicited_multicast_addr;  /* Solicited-node multicast */
	
	odp_time_t    creation_time;             /* Time of entry creation (in seconds).*/
	uint32_t      lifetime;                  /* Address lifetime (in seconds). 0xFFFFFFFF = Infinite Lifetime
	                                          * RFC4862. A link-local address has an infinite preferred and valid lifetime; it
	                                          * is never timed out.*/
	uint8_t       prefix_length;             /* Prefix length (in bits). The number of leading bits
	                                          * in the Prefix that are valid. */
	uint32_t      dad_transmit_counter;      /* Counter used by DAD. Equals to the number
	                                          * of NS transmits till DAD is finished.*/
	odp_time_t    state_time;                /* Time of last state event.*/
	unsigned      type  : 2;                 /* How the address was acquired. */
	unsigned      state : 1;                 /* Address current state. (fnet_netif_ip6_addr_state_t)*/
	unsigned      used : 1;                  /* Is the entry in use? */
} ipv6_nif_addr_t;

typedef struct
{
	ipv6_addr_t   multicast;    /* IPv6 address. */
	unsigned      refc : 29;    /* Usage counter. */
	unsigned      used : 1;     /* Entry in use? */
	unsigned      reported : 1; /* MLD-Report sent? */
	unsigned      mlddone : 1;  /* MLD-Done sent? */
} ipv6_nif_multicast_t;

struct ipv6_nif_struct{
	odp_spinlock_t           fields_lock;
	odp_spinlock_t           address_lock;
	odp_spinlock_t           multicast_lock;
	ipv6_nif_addr_t          addrs[IPV6_NIF_ADDR_MAX];
	ipv6_nif_multicast_t     multicasts[IPV6_NIF_MULTCAST_MAX];
	uint8_t                  hop_limit;
	uint32_t                 mtu;  /* MTU */
	uint32_t                 pmtu; /* PMTU (later). */
	uint32_t                 base_reachable_time;
	uint32_t                 reachable_time;
	uint32_t                 retrans_timer;
	unsigned                 disabled : 1; /* < IPv6 is Disabled*/
	unsigned                 pmtu_on : 1;  /* < IPv6/ICMPv6 PMTU Enabled*/
};

void fastnet_ipv6_init(struct ipv6_nif_struct *ipv6);

int fastnet_ipv6_deactivated(struct ipv6_nif_struct *ipv6);
int fastnet_ipv6_addr_is_self(struct ipv6_nif_struct *ipv6, ipv6_addr_t *addr);
int fastnet_ipv6_addr_is_own_ip6_solicited_multicast(struct ipv6_nif_struct *ipv6, ipv6_addr_t *addr);

/* Select the best source-IP for the destination-IP (see RFC3484 .5: Source Address Selection) */
int fastnet_ipv6_addr_select(struct ipv6_nif_struct *ipv6, ipv6_addr_t *src, ipv6_addr_t *dest);

/* Adds an IPv6 address to the interface. */
int fastnet_ipv6_addr_add(struct ipv6_nif_struct *ipv6, ipv6_addr_t *addr,uint8_t prefix);

/* Adds an IPv6 autoconf-address to the interface. */
int fastnet_ipv6_addr_autoconf(nif_t *nif);


