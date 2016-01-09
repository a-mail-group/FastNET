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


/**
 * @brief Neighbor Solicitation.
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 */
void fstn_nd6_neighbor_solicitation_receive(odp_packet_t pkt, thr_s* thr);

/**
 * @brief Neighbor Advertisemnt.
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 */
void fstn_nd6_neighbor_advertisement_receive(odp_packet_t pkt, thr_s* thr);

/**
 * @brief Router Advertisemnt.
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 */
void fstn_nd6_router_advertisement_receive(odp_packet_t pkt, thr_s* thr);

/**
 * @brief Redirect.
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 */
void fstn_nd6_redirect_receive(odp_packet_t pkt, thr_s* thr);








