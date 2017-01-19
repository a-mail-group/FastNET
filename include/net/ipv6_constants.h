/*
 *   Copyright 2017 Simon Schmidt
 *   Copyright 2011-2016 by Andrey Butok. FNET Community.
 *   Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
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

#include <net/header/ip6.h>

/* RFC4484:
 *  Multicast destination addresses have a 4-bit scope field that
 *  controls the propagation of the multicast packet.  The IPv6
 *  addressing architecture defines scope field values for interface-
 *  local (0x1), link-local (0x2), subnet-local (0x3), admin-local (0x4),
 *  site-local (0x5), organization-local (0x8), and global (0xE)
 *  scopes [11].
 */
#define FNET_IP6_ADDR_SCOPE_INTERFACELOCAL (0x01)
#define FNET_IP6_ADDR_SCOPE_LINKLOCAL      (0x02)
#define FNET_IP6_ADDR_SCOPE_SITELOCAL      (0x05)
#define FNET_IP6_ADDR_SCOPE_ORGLOCAL       (0x08)
#define FNET_IP6_ADDR_SCOPE_GLOBAL         (0x0e)

uint32_t fastnet_ipv6_scope(ipv6_addr_t ip_addr);
uint32_t fastnet_ipv6_policy_label(ipv6_addr_t ip_addr);

int fastnet_ipv6_common_prefix(const ipv6_addr_t *addr1,const ipv6_addr_t *addr2);