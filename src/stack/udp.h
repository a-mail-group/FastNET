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

/*
 * @brief processes an UDP packet
 * @param  pkt     the packet
 * @param  thr     the thread-local struct
 * @return  true if packet has been consumed, false otherwise
 * 
 * This function processes an UDP packet
 */
int fstn_udp_input(odp_packet_t pkt, thr_s* thr);


