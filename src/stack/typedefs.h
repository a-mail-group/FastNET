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
#include <odp/helper/eth.h>
//#include <stdint.h>

typedef struct {
	odph_ethaddr_t eth_address;
	uint32be_t     ipv4_address;
	uint32be_t     ipv4_netbroadcast;
} netif_s;

typedef struct {
	netif_s* netif;
} thr_s;



