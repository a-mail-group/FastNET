/*
 *   Copyright 2016-2017 Simon Schmidt
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

typedef union{
	struct{
		odp_packet_t next;
	};
} fastnet_pkt_uarea_t;

#define FASTNET_PACKET_UAREA(pkt) ((fastnet_pkt_uarea_t*)odp_packet_user_area(pkt))

