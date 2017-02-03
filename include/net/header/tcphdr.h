/*
 *   Copyright 2016-2017 Simon Schmidt
 * Copyright 2011-2015 by Andrey Butok. FNET Community.
 * Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
 * Copyright 2003 by Alexey Shervashidze, Andrey Butok. Motorola SPS
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

/************************************************************************
*    TCP header structure. //TBD use it instead of definitions.
*************************************************************************/
typedef struct ODP_PACKED
{
    uint16_t   source_port     ;       /* Source port number.*/
    uint16_t   destination_port    ;   /* Destination port number.*/
    uint32_t   sequence_number     ;   /* Sequence Number.*/
    uint32_t   ack_number  ;           /* Ack Number.*/
    uint16_t   hdrlength__flags ;      /* (4 bits) Number of 32 bit words in the TCP Header. (6 bits) Reserved. (6bits) Flags.*/
    uint16_t   window  ;               /* Window.*/
    uint16_t   checksum    ;           /* Checksum.*/
    uint16_t   urgent_ptr  ;           /* Urgent pointer.*/
} fnet_tcp_header_t;

typedef struct ODP_PACKED
{
    uint32_t   sequence_number     ;   /* Sequence Number.*/
    uint32_t   ack_number  ;           /* Ack Number.*/
    uint16_t   hdrlength__flags ;      /* (4 bits) Number of 32 bit words in the TCP Header. (6 bits) Reserved. (6bits) Flags.*/
    uint16_t   window  ;               /* Window.*/
    uint16_t   checksum    ;           /* Checksum.*/
    uint16_t   urgent_ptr  ;           /* Urgent pointer.*/
} fnet_tcp_parthdr_t;

/* Offset of the checksum field. */
#define TCP_HDR_CHECKSUM_OFFSET 16

#define FNET_TCP_SGT_FIN            0x01
#define FNET_TCP_SGT_SYN            0x02
#define FNET_TCP_SGT_RST            0x04
#define FNET_TCP_SGT_PSH            0x08
#define FNET_TCP_SGT_ACK            0x10
#define FNET_TCP_SGT_URG            0x20

