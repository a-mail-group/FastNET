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
#include <net/ip6_next_hop.h>
#include <net/ipv6.h>
#include <net/header/ip6hdr.h>
#include <net/header/ip6defs.h>
#include <net/header/ethhdr.h>
#include <net/packet_output.h>
#include <net/ipv6_mac_cache.h>
#include <net/requirement.h>
#include <net/std_defs.h>
#include <net/_config.h>

struct ip6_local_info{
	ip6_next_hop_t*    nh;
	ip6_next_hop_t     nh_local;
	fnet_ip6_header_t* ip6;
	nif_t*             ctxnif;
	nif_t*             outnif;
	int                is_loopback;
};

static
netpp_retcode_t ipv6_find_route(struct ip6_local_info* __restrict__  odata){
	ipv6_addr_t dst = odata->ip6->destination_addr;
	ipv6_addr_t src = odata->ip6->source_addr;
	
	/*
	 * TODO:
	 * RFC4861 7.2.  Address Resolution
	 * Address resolution is performed only on addresses that are determined
	 * to be on-link and for which the sender does not know the corresponding
	 * link-layer address (see Section 5.2).
	 *
	 * NOTE: If the Address is not on-link, 
	 */
	
	/* TODO: Possible redirection. */
	
	if(odata->nh == NULL){
		/*
		 * Link-local IPv6 addresses do not use gateways.
		 */
		if(IP6_ADDR_IS_LINKLOCAL(dst)){
			odata->nh_local.ip6_gateway = dst;
			odata->nh_local.nif = odata->ctxnif;
			odata->nh = &(odata->nh_local);
			goto nh_done;
		}
		
		/*
		 * XXX Gateways are not supported yet, until we support routers.
		 */
		odata->nh_local.ip6_gateway = dst;
		odata->nh_local.nif = odata->ctxnif;
		odata->nh = &(odata->nh_local);
	}
nh_done:
	
	odata->outnif = odata->nh->nif;
	
	/*
	 * Null-pointer check.
	 */
	if(odp_unlikely(odata->outnif == NULL)){
		NET_LOG("!odata->outnif\n");
		return NETPP_DROP;
	}
	
	return NETPP_CONTINUE;
}

static uint64_t ipv6_multicast(ipv6_addr_t addr){
	union {
		uint8_t  addr8[8];
		uint64_t addr64 ODP_PACKED;
	} mac;
	
	mac.addr8[0] = 0x33;
	mac.addr8[1] = 0x33;
	mac.addr8[2] = addr.addr[12];
	mac.addr8[3] = addr.addr[13];
	mac.addr8[4] = addr.addr[14];
	mac.addr8[5] = addr.addr[15];
	mac.addr8[6] = 0;
	mac.addr8[7] = 0;
	return mac.addr64;
}

static void ipv6_setmacaddrs(fnet_eth_header_t* __restrict__ ethp, uint64_t src, uint64_t dst){
	union {
		uint8_t  addr8[8];
		uint64_t addr64 ODP_PACKED;
	} srci = { .addr64 = src };
	
	union {
		uint8_t  addr8[8];
		uint64_t addr64 ODP_PACKED;
	} dsti = { .addr64 = dst };
	
	ethp->destination_addr[0] = dsti.addr8[0];
	ethp->destination_addr[1] = dsti.addr8[1];
	ethp->destination_addr[2] = dsti.addr8[2];
	ethp->destination_addr[3] = dsti.addr8[3];
	ethp->destination_addr[4] = dsti.addr8[4];
	ethp->destination_addr[5] = dsti.addr8[5];
	
	ethp->source_addr[0] = srci.addr8[0];
	ethp->source_addr[1] = srci.addr8[1];
	ethp->source_addr[2] = srci.addr8[2];
	ethp->source_addr[3] = srci.addr8[3];
	ethp->source_addr[4] = srci.addr8[4];
	ethp->source_addr[5] = srci.addr8[5];
	
	ethp->type = odp_cpu_to_be_16(NETPROT_L3_IPV6);
}


netpp_retcode_t ipv6_add_eth(odp_packet_t pkt,struct ip6_local_info* __restrict__  odata){
	netpp_retcode_t res;
	uint32_t ethsize,ipoff;
	void* ethp;
	//int hasifip;
	int sendnd6;
	uint64_t src,dst;
	ipv6_addr_t dst_ip = odata->nh->ip6_gateway;
	//ipv6_addr_t ifip;
	// TODO: loopback support.
	
	
	ethsize = sizeof(fnet_eth_header_t);
	ipoff = odp_packet_l3_offset(pkt);
	
	src = odata->outnif->hwaddr;
	
	/*
	 * RFC4861 7.2. Address Resolution:
	 *   Address resolution is never performed on multicast addresses.
	 *
	 * If destination Address is a multicast, derive Multicast-MAC from it.
	 */
	if(IP6_ADDR_IS_MULTICAST(dst_ip)){
		dst = ipv6_multicast(dst_ip);
	}else{
		/* TODO: Only on-Link addresses may be looked up.*/
		
		/*
		 * Check Neigbor cache.
		 */
		res = fastnet_ipv6_mac_lookup(odata->outnif,dst_ip,&dst,&sendnd6,pkt);
		
		if(sendnd6){
			/*
			 * Send an ND6 packet out the network interface.
			 */
			//fastnet_arp_output(ifip,dst_ip,odata->outnif);
		}
		if(res!=NETPP_CONTINUE) return res;
	}
	
	if(ipoff >= ethsize){
		odp_packet_l2_offset_set(pkt,ipoff-ethsize);
		ethp = odp_packet_l2_ptr(pkt,NULL);
	}else{
		ethp = odp_packet_push_head(pkt,ethsize-ipoff);
		odp_packet_l2_offset_set(pkt,0);
		odp_packet_l3_offset_set(pkt,ethsize);
	}
	
	if(odp_unlikely(ethp == NULL)) return NETPP_DROP;
	
	ipv6_setmacaddrs(ethp,src,dst);
	
	return NETPP_DROP;
}

netpp_retcode_t fastnet_ip6_output(odp_packet_t pkt,ip6_next_hop_t* nh){
	uint32_t pretrail;
	netpp_retcode_t ret;
	struct ip6_local_info odata;
	
	odata.nh = nh;
	odata.ip6 = odp_packet_l3_ptr(pkt,NULL);
	NET_ASSERT(odata.ip6 != NULL, "Layer 3 pointer is required!");
	
	odata.ctxnif = odp_packet_user_ptr(pkt);
	odata.outnif = NULL;
	odata.is_loopback = 0;
	
	ret = ipv6_find_route(&odata);
	if(odp_unlikely(ret != NETPP_CONTINUE)) return ret;
	
	ret = ipv6_add_eth(pkt,&odata);
	if(odp_unlikely(ret != NETPP_CONTINUE)) return ret;
	
	if(odata.is_loopback)
		return fastnet_pkt_loopback(pkt,odata.outnif);
	else{
		/*
		 * Do we have any data in front of the Layer 2 header? Get Rid of it!
		 */
		pretrail = odp_packet_l2_offset(pkt);
		if(odp_unlikely(pretrail>0))
			odp_packet_pull_head(pkt,pretrail);
		
		return fastnet_pkt_output(pkt,odata.outnif);
	}
}


