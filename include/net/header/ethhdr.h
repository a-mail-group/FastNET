/*
 *   Copyright 2016-2017 Simon Schmidt
 * Copyright 2011-2016 by Andrey Butok. FNET Community.
 * Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
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


/*
 * The 'EtherType' value for implemented protocols like IP and ARP.
 */
#define NETPROT_L3_IPV4   0x0800
#define NETPROT_L3_ARP    0x0806

#define NETPROT_L3_IPV6   0x86DD

typedef struct ODP_PACKED
{
    uint8_t destination_addr[6]    ;   /**< 48-bit destination address.*/
    uint8_t source_addr[6]         ;   /**< 48-bit source address.*/
    uint16_t   type                ;   /**< 16-bit type field.*/
} fnet_eth_header_t;

