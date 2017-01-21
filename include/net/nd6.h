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
#include <net/types.h>

netpp_retcode_t fastnet_nd6_nsol_input(odp_packet_t pkt,int source_is_unspecified);
netpp_retcode_t fastnet_nd6_nadv_input(odp_packet_t pkt,int is_dest_multicast);

#if 0

netpp_retcode_t fastnet_nd6_rsol_input(odp_packet_t pkt);
netpp_retcode_t fastnet_nd6_radv_input(odp_packet_t pkt);
#endif

