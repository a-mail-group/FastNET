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
#include <net/ip_next_hop.h>
#include <net/ipv4.h>
#include <net/_config.h>
#include <net/header/iphdr.h>
#include <net/header/ethhdr.h>
#include <net/packet_output.h>
#include <net/checksum.h>
#include <net/ipv4_mac_cache.h>
#include <net/requirement.h>
#include <net/std_defs.h>

struct ip_local_info{
	ip_next_hop_t*    nh;
	ip_next_hop_t     nh_local;
	fnet_ip_header_t* ip;
	nif_t*            ctxnif;
	nif_t*            outnif;
	int               is_loopback;
};

static
netpp_retcode_t ipv4_find_route(struct ip_local_info* __restrict__  odata){
	ipv4_addr_t dst = odata->ip->desination_addr;
	ipv4_addr_t src = odata->ip->source_addr;
	if(odata->nh == NULL){
		if(odp_likely(odata->ctxnif != NULL)){
			/*
			 * If the IP address is link-local, then,
			 * use the target address as gateway.
			 */
			if(fastnet_ip_onlink(odata->ctxnif->ipv4,dst)){
				odata->nh_local.ip_gateway = dst;
				odata->nh_local.nif = odata->ctxnif;
				odata->nh = &(odata->nh_local);
				goto nh_done;
			}
		}
		/* TODO: find route. */
		return NETPP_DROP;
	}
nh_done:
	
	odata->outnif = odata->nh->nif;
	
	/* Null-pointer check. */
	if(odp_unlikely(odata->outnif == NULL)){
		NET_LOG("!odata->outnif\n");
		return NETPP_DROP;
	}
	
	/*
	 * If the Upper layer has not filled out
	 * the source IP, we have to do it.
	 */
	if (odata->ip->desination_addr == 0) {
		/* Null-pointer check. */
		if(odp_unlikely(odata->outnif->ipv4 == NULL)) {
			NET_LOG("!odata->outnif->ipv4\n");
			return NETPP_DROP;
		}
		
		odata->ip->desination_addr = odata->outnif->ipv4->address;
	}
	return NETPP_CONTINUE;
}

static uint64_t ipv4_multicast(ipv4_addr_t addr){
	union {
		uint8_t  addr8[4];
		uint32_t addr32 ODP_PACKED;
	} ip = { .addr32=addr };
	union {
		uint8_t  addr8[8];
		uint64_t addr64 ODP_PACKED;
	} mac;
	
	mac.addr8[0] = 0x01;
	mac.addr8[1] = 0x00;
	mac.addr8[2] = 0x5e;
	mac.addr8[3] = ip.addr8[1] & 0x7f;
	mac.addr8[4] = ip.addr8[2];
	mac.addr8[5] = ip.addr8[3];
	mac.addr8[6] = 0;
	mac.addr8[7] = 0;
	return mac.addr64;
}

static void ipv4_setmacaddrs(fnet_eth_header_t* __restrict__ ethp, uint64_t src, uint64_t dst){
	union {
		uint8_t  addr8[8];
		uint64_t addr64 ODP_PACKED;
	} srci = { .addr64 = src };
	
	union {
		uint8_t  addr8[8];
		uint64_t addr64 ODP_PACKED;
	} dsti = { .addr64 = dst };
	
	ethp->destination_addr[0] = srci.addr8[0];
	ethp->destination_addr[1] = srci.addr8[1];
	ethp->destination_addr[2] = srci.addr8[2];
	ethp->destination_addr[3] = srci.addr8[3];
	ethp->destination_addr[4] = srci.addr8[4];
	ethp->destination_addr[5] = srci.addr8[5];
	
	ethp->source_addr[0] = dsti.addr8[0];
	ethp->source_addr[1] = dsti.addr8[1];
	ethp->source_addr[2] = dsti.addr8[2];
	ethp->source_addr[3] = dsti.addr8[3];
	ethp->source_addr[4] = dsti.addr8[4];
	ethp->source_addr[5] = dsti.addr8[5];
	
	ethp->type = NETPROT_L3_IPV4;
}

static
netpp_retcode_t ipv4_add_eth(odp_packet_t pkt,struct ip_local_info* __restrict__  odata) {
	netpp_retcode_t res;
	uint32_t ethsize,ipoff;
	void* ethp;
	int hasifip;
	int sendarp;
	uint64_t src,dst;
	ipv4_addr_t dst_ip = odata->ip->desination_addr;
	ipv4_addr_t ifip;
	
	
	if(odp_likely(odata->outnif->ipv4 != NULL)){
		hasifip = 1;
		ifip = odata->outnif->ipv4->address;
	}else{
		hasifip = 0;
	}
	
	ethsize = sizeof(fnet_eth_header_t);
	ipoff = odp_packet_l3_offset(pkt);
	
	src = odata->outnif->hwaddr;
	if(IP4_ADDR_IS_MULTICAST(dst_ip)){
		dst = ipv4_multicast(dst_ip);
	}else if(hasifip && ifip == dst_ip){
		odata->is_loopback = 1;
		dst = odata->outnif->hwaddr;
	}else{
		res = fastnet_ipv4_mac_lookup(odata->outnif,dst_ip,&dst,&sendarp,pkt);
		if(res!=NETPP_CONTINUE){
			/*
			 * Send an ARP packet out the network interface.
			 * XXX test return value.
			 */
			fastnet_arp_output(ifip,dst_ip,odata->outnif);
			return res;
		}
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
	
	ipv4_setmacaddrs(ethp,src,dst);
	
	return NETPP_CONTINUE;
}

static
netpp_retcode_t arpres_add_eth(odp_packet_t pkt,uint64_t src,uint64_t dst){
	uint32_t ethsize,ipoff;
	void* ethp;
	
	ethsize = sizeof(fnet_eth_header_t);
	ipoff = odp_packet_l3_offset(pkt);
	
	if(ipoff >= ethsize){
		odp_packet_l2_offset_set(pkt,ipoff-ethsize);
		ethp = odp_packet_l2_ptr(pkt,NULL);
	}else{
		ethp = odp_packet_push_head(pkt,ethsize-ipoff);
		odp_packet_l2_offset_set(pkt,0);
		odp_packet_l3_offset_set(pkt,ethsize);
	}
	
	if(odp_unlikely(ethp == NULL)) return NETPP_DROP;
	
	ipv4_setmacaddrs(ethp,src,dst);
	
	return NETPP_CONTINUE;
}

netpp_retcode_t fastnet_ip_output(odp_packet_t pkt,ip_next_hop_t* nh){
	uint32_t pretrail;
	netpp_retcode_t ret;
	struct ip_local_info odata;
	
	odata.nh = nh;
	odata.ip = odp_packet_l3_ptr(pkt,NULL);
	NET_ASSERT(odata.ip != NULL, "Layer 3 pointer is required!");
	
	odata.ctxnif = odp_packet_user_ptr(pkt);
	odata.outnif = NULL;
	odata.is_loopback = 0;
	
	ret = ipv4_find_route(&odata);
	if(odp_unlikely(ret != NETPP_CONTINUE)) return ret;
	
	odata.ip->checksum = fastnet_checksum(pkt,odp_packet_l3_offset(pkt),0,odata.outnif,0); // NIFOFL_IP4_CKSUM
	
	ret = ipv4_add_eth(pkt,&odata);
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

void fastnet_ip_arp_transmit(odp_packet_t pkt,nif_t *nif,uint64_t src,uint64_t dst){
	uint32_t pretrail;
	netpp_retcode_t ret;
	odp_packet_t pkt_next;
	
	while(pkt!=ODP_PACKET_INVALID){
		
		pkt_next = FASTNET_PACKET_UAREA(pkt)->next;
		
		ret = arpres_add_eth(pkt,src,dst);
		if(odp_unlikely(ret != NETPP_CONTINUE)){
			if(ret==NETPP_DROP) odp_packet_free(pkt);
			pkt = pkt_next;
			continue;
		}
		/*
		 * Do we have any data in front of the Layer 2 header? Get Rid of it!
		 */
		pretrail = odp_packet_l2_offset(pkt);
		if(odp_unlikely(pretrail>0))
			odp_packet_pull_head(pkt,pretrail);
		
		ret = fastnet_pkt_output(pkt,nif);
		if(odp_unlikely(ret != NETPP_CONSUMED)){
			odp_packet_free(pkt);
		}
		pkt = pkt_next;
	}
}

