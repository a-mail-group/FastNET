/*
 *
 * Copyright 2016 Simon Schmidt
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

#pragma once

#include <odp.h>
#include "typedefs.h"

static const odph_ethaddr_t fstn_eth_null_addr = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
static const odph_ethaddr_t fstn_eth_broadcast_addr = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };


/*
 * @brief processes an input packet
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function processes an odp-packet.
 */
void fstn_pkt_input(odp_packet_t pkt, thr_s* thr);

/*
 * @brief sends an ethernet packet
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * 
 * This function sends an ethernet packet.
 * IMPORTANT: The checksum shall be appended by this function!
 */
void fstn_eth_output(odp_packet_t pkt, thr_s* thr);


