/*
 *
 * Copyright 2016 Simon Schmidt
 * Copyright 2011-2015 by Andrey Butok. FNET Community.
 * Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * This file is derived from FNET as of version 3.0.0
 */

#pragma once

#include "ip_addr_ext.h"

/************************************************************************
*    Definitions of five different classes.
*************************************************************************/
#define FNET_IP4_CLASS_A(i)     !((i).addr[0]&0x80)
#define FNET_IP4_CLASS_A_NET    FNET_HTONL(0xff000000U)

#define FNET_IP4_CLASS_B(i)     (((i).addr[0]&0xC0) == 0x80)
#define FNET_IP4_CLASS_B_NET    FNET_HTONL(0xffff0000U)

#define FNET_IP4_CLASS_C(i)     (((i).addr[0]&0xE0) == 0xC0)
#define FNET_IP4_CLASS_C_NET    FNET_HTONL(0xffffff00U)

#define FNET_IP4_CLASS_D(i)     (((i).addr[0]&0xF0) == 0xE0)
#define FNET_IP4_CLASS_D_NET    FNET_HTONL(0xf0000000U)

/* Host groups are identified by class D IP addresses.*/
#define FNET_IP4_ADDR_IS_MULTICAST(addr)   FNET_IP4_CLASS_D(addr)

#define FNET_IP4_ADDR_IS_UNSPECIFIED(addr) !(addr).as_odp

#define FNET_IP4_CLASS_E(i)     (((i).addr[0]&0xF0) == 0xF0)
#define FNET_IP4_EXPERIMENTAL(i) FNET_IP4_CLASS_E(i)
#define FNET_IP4_BADCLASS(i)     FNET_IP4_CLASS_E(i)

#define FNET_IP4_ADDR1(ipaddr)   ((fnet_uint8_t)(fnet_ntohl(ipaddr) >> 24U) & 0xffU)
#define FNET_IP4_ADDR2(ipaddr)   ((fnet_uint8_t)(fnet_ntohl(ipaddr) >> 16U) & 0xffU)
#define FNET_IP4_ADDR3(ipaddr)   ((fnet_uint8_t)(fnet_ntohl(ipaddr) >> 8U) & 0xffU)
#define FNET_IP4_ADDR4(ipaddr)   ((fnet_uint8_t)(fnet_ntohl(ipaddr)) & 0xffU)

#define FSTN_IP4_BROADCAST      0xFFFFFFFFU

