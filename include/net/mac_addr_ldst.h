/*
 *   Copyright 2017 Simon Schmidt
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

static uint64_t fastnet_mac_to_int(uint8_t* __restrict__ macp){
	union {
		uint8_t  addr8[8];
		uint64_t addr64 ODP_PACKED;
	} mac = { .addr64 = 0 };
	mac.addr8[0] = macp[0];
	mac.addr8[1] = macp[1];
	mac.addr8[2] = macp[2];
	mac.addr8[3] = macp[3];
	mac.addr8[4] = macp[4];
	mac.addr8[5] = macp[5];
	mac.addr8[6] = 0;
	mac.addr8[7] = 0;
	return mac.addr64;
}

static uint64_t fastnet_int_to_mac(uint8_t* __restrict__ macp,uint64_t value){
	union {
		uint8_t  addr8[8];
		uint64_t addr64 ODP_PACKED;
	} mac = { .addr64 = value };
	macp[0] = mac.addr8[0];
	macp[1] = mac.addr8[1];
	macp[2] = mac.addr8[2];
	macp[3] = mac.addr8[3];
	macp[4] = mac.addr8[4];
	macp[5] = mac.addr8[5];
	return mac.addr64;
}

