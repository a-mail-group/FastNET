/**************************************************************************
*
* Copyright 2011-2015 by Andrey Butok. FNET Community.
* Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
*
*  Licensed under the Apache License, Version 2.0 (the "License"); you may
*  not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*/ 

/*
 * This file is derived from FNET as of version 3.0.0
 */

/*!
*
* @file fnet_arp.h
*
* @author Andrey Butok
*
* @brief Private. ARP protocol function definitions, data structures, etc
*
*/

#ifndef _FNET_ARP_H_

#define _FNET_ARP_H_

#include <odp.h>
#include <odp/helper/eth.h>

/*
 *    ARP definitions
 */
#define FNET_ARP_HARD_TYPE      (1U)         /* for Ethernet.*/

#define FNET_ARP_HARD_SIZE      (6U)         /* for Ethernet.*/
#define FNET_ARP_PROT_SIZE      (4U)         /* for IP.*/

#define FNET_ARP_OP_REQUEST     (1U)         /* ARP request.*/
#define FNET_ARP_OP_REPLY       (2U)         /* ARP reply.*/

/**
 * @internal
 * @brief    ARP header structure.
 */
typedef struct ODP_PACKED
{
    uint16_t   hard_type;            /**< The type of hardware address (=1 for Ethernet).*/
    uint16_t   prot_type;            /**< The type of protocol address (=0x0800 for IP).*/
    uint8_t    hard_size;            /**< The size in bytes of the hardware address (=6).*/
    uint8_t    prot_size;            /**< The size in bytes of the protocol address (=4).*/
    uint16_t   op;                   /**< Opcode.*/
    odph_ethaddr_t sender_hard_addr; /**< Hardware address of sender of this packet.*/
    uint32be_t sender_prot_addr;     /**< Protocol address of sender of this packet.*/
    odph_ethaddr_t target_hard_addr; /**< Hardware address of target of this packet.*/
    uint32be_t targer_prot_addr;     /**< Protocol address of target of this packet.*/
} fnet_arp_header_t;

#endif

