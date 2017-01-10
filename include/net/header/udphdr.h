/*
 *   Copyright 2016-2017 Simon Schmidt
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

/************************************************************************
*     UDP definitions
*************************************************************************/
#define FNET_UDP_TTL            (64u)                       /* Default TTL.*/
#define FNET_UDP_TTL_MULTICAST  (1u)                        /* Default TTL for Multicast datagrams.
                                                             * RFC112 6.1: If the upper-layer protocol
                                                             * chooses not to specify a time-to-live, it should
                                                             * default to 1 for all multicast IP datagrams, so that an explicit
                                                             * choice is required to multicast beyond a single network.
                                                             */
#if 0
#define FNET_UDP_DF             (FNET_FALSE)                       /* DF flag.*/
#define FNET_UDP_TX_BUF_MAX     (FNET_CFG_SOCKET_UDP_TX_BUF_SIZE) /* Default maximum size for send socket buffer.*/
#define FNET_UDP_RX_BUF_MAX     (FNET_CFG_SOCKET_UDP_RX_BUF_SIZE) /* Default maximum size for receive socket buffer.*/
#endif

#include <odp_api.h>

typedef struct ODP_PACKED
{
    uint16_t source_port ;      /* Source port number.*/
    uint16_t destination_port ; /* Destination port number.*/
    uint16_t length ;           /* Length.*/
    uint16_t checksum ;         /* Checksum.*/
} fnet_udp_header_t;

