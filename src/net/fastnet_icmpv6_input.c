/*
 *   Copyright 2017 Simon Schmidt
 *   Copyright 2011-2016 by Andrey Butok. FNET Community.
 *   Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
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
#include <net/packet_input.h>
#include <net/packet_output.h>
#include <net/header/icmp6.h>
#include <net/header/ip6hdr.h>
#include <net/checksum.h>
#include <net/header/layer4.h>
#include <net/_config.h>
#include <net/defaults.h>

netpp_retcode_t fastnet_icmpv6_input(odp_packet_t pkt){
	fnet_icmp6_header_t *hdr;
	fnet_icmp6_err_header_t *icmp6_err;
	
	
	
	return NETPP_DROP;
}