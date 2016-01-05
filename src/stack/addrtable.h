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

#include "typedefs.h"
#include "ip_addr.h"
#include <odp/helper/eth.h>


void fstn_eth_ipv4_entry(thr_s* thr, fstn_ipv4_t ip,odph_ethaddr_t eth);
void fstn_eth_ipv6_entry(thr_s* thr, fstn_ipv6_t ip,odph_ethaddr_t eth);



