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
#include <net/in_tlp.h>
#include <net/std_lib.h>
#include <net/ipv4_mac_cache.h>
#include <net/std_defs.h>
#include <net/header/layer4.h>

#if 1
#define ASSERT(i) if(!(i)) fastnet_abort()
#else
#define ASSERT(i) (void)0
#endif

/*
 * The Default IPv6 handler is a wrapper around a standard IPv4 handler.
 * The next header is set to IP_NO_PROTOCOL, which indicates, that there is no next header to process.
 */
static
netpp_retcode_t def_ipv6_handler(odp_packet_t pkt,int* nxt, int idx){
	*nxt = IP_NO_PROTOCOL;
	return fn_in_protocols[idx].in_hook(pkt);
}

/*
 * The Drop-Hook advises the protocol handling stack to drop the packet.
 */
static
netpp_retcode_t drop_hook(odp_packet_t pkt){
	return NETPP_DROP;
}

static void init(){
	int i;
	int idefault = -1;
	int idefault6 = -1;
	
	ASSERT(fn_in_protocols_n>0);
	
	/* Find IPv4 default protocol handler. */
	for(i=0;i<fn_in_protocols_n;++i){
		if(fn_in_protocols[i].in_pt!=INPT_DEFAULT) continue;
		idefault = i;
		break;
	}
	
	/* Find IPv6 default protocol handler. */
	for(i=0;i<fn_in_protocols_n;++i){
		if(fn_in_protocols[i].in_pt!=INPT_DEFAULT6) continue;
		idefault6 = i;
		break;
	}
	
	ASSERT(idefault >=0);
	
	/*
	 * If there is no IPv6 Default Routine, fall back to the IPv4 variant.
	 */
	if(idefault6<0) idefault6 = idefault;
	
	/*
	 * Set all protocol/next-header fields to their default values.
	 */
	for(i=0;i<256;++i){
		fn_in4_protocol_idx[i] = idefault;
		fn_in6_protocol_idx[i] = idefault6;
	}
	
	/*
	 * Scan all transport layer handlers.
	 */
	for(i=0;i<fn_in_protocols_n;++i){
		switch(fn_in_protocols[i].in_pt){
		case INPT_PROTOCOL:
			fn_in4_protocol_idx[fn_in_protocols[i].in_protocol] = i;
		case INPT_IPV6_ONLY:
			fn_in6_protocol_idx[fn_in_protocols[i].in_protocol] = i;
			break;
		case INPT_IPV4_ONLY:
			fn_in4_protocol_idx[fn_in_protocols[i].in_protocol] = i;
			break;
		}
		
		/*
		 * If there is no in6_hook defined, create one.
		 */
		if(fn_in_protocols[i].in6_hook == NULL)
			fn_in_protocols[i].in6_hook = def_ipv6_handler;
		
		/*
		 * if no IPv4 hook is defined, set the drop-hook as handler (safety feature)!
		 */
		if(fn_in_protocols[i].in_hook == NULL)
			fn_in_protocols[i].in_hook = drop_hook;
		
		/*
		 * Initialize the Protocol if such an initialization routine exists.
		 */
		if(fn_in_protocols[i].tlp_init != NULL)
			fn_in_protocols[i].tlp_init();
	}
}


void fastnet_tlp_init(){
	fastnet_initialize_ipmac_cache();
	init();
}

