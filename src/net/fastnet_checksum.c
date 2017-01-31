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
#include <net/checksum.h>
#include <net/header/iphdr.h>
#include <net/header/ip6hdr.h>
#include <net/safe_packet.h>

static inline uint16_t cksum_finalize(uint32_t chk){
	uint16_t res = (uint16_t)chk;
	return ~res;
}

static inline uint16_t cksum_cast(uint32_t chk){
	uint16_t res = (uint16_t)chk;
	return res;
}

static inline 
uint32_t l4_sum_part(uint16_t* __restrict__ data,uint32_t checksum,uint32_t words){
	
	while( words-- ) checksum += *(data++);
	
	checksum = (checksum>>16) + (checksum & 0xffff);
	
	return checksum;
}

uint16_t fastnet_ipv4_hdr_checksum(odp_packet_t pkt){
	uint32_t length,cksum,max,off;
	void* ptr;
	
	off = odp_packet_l3_offset(pkt);
	
	/*
	 * XXX
	 * Here, We blindly assume, the header is in contigous space.
	 */
	
	ptr = odp_packet_offset(pkt,off,&length,NULL);
	/* Obtain IPv4 header length. */
	max = ((*((uint8_t*)ptr))&0xf)*4;
	if(length>max) length=max;
	
	cksum = l4_sum_part((uint16_t*)ptr,0,length/2);
	cksum = (cksum>>16) + (cksum & 0xffff);
	return cksum_finalize(cksum);
}

uint16_t fastnet_checksum(odp_packet_t pkt,uint32_t offset,uint32_t cksuminit,nif_t* nif,uint32_t offload_flags){
	uint32_t length;
	uint8_t* bptr;
	union {
		uint8_t  repr8[2];
		uint16_t repr16 ODP_PACKED;
	} gap = { .repr16 = 0 };
	int gap_i = 0;
	if(odp_likely(nif != NULL)){
		if(odp_unlikely(nif->offload_flags & offload_flags)) return 0;
	}
	
	cksuminit = (cksuminit >> 16) + (cksuminit & 0xffff);
	
	for(;;){
		bptr = odp_packet_offset(pkt,offset,&length,NULL);
		if(length==0) break;
		offset+=length;
		if(gap_i){
			gap.repr8[1] = *bptr;
			cksuminit += gap.repr16;
			bptr++;
			length--;
		}
		cksuminit = l4_sum_part((uint16_t*)bptr,cksuminit,length/2);
		gap_i = length&1;
		if(gap_i){
			gap.repr8[0] = bptr[length-1];
		}
	}
	if(gap_i){
		gap.repr8[1] = 0;
		cksuminit += gap.repr16;
	}
	cksuminit = (cksuminit >> 16) + (cksuminit & 0xffff);
	cksuminit = (cksuminit >> 16) + (cksuminit & 0xffff);
	return cksum_finalize(cksuminit);
}

uint16_t fastnet_ip_ph(ipv4_addr_t src,ipv4_addr_t dst,uint8_t prot){
	struct ODP_PACKED{
		ipv4_addr_t src;
		ipv4_addr_t dst;
		uint8_t     zero;
		uint8_t     prot;
	} ph = { src,dst,0,prot };
	uint32_t cksum = l4_sum_part((uint16_t*)&ph,0,sizeof(ph));
	cksum = (cksum>>16) + (cksum&0xffff);
	cksum = (cksum>>16) + (cksum&0xffff);
	return cksum_cast(cksum);
}
uint16_t fastnet_ip6_ph(ipv6_addr_t src,ipv6_addr_t dst,uint8_t prot){
	struct ODP_PACKED{
		ipv6_addr_t src;
		ipv6_addr_t dst;
		uint8_t     zero;
		uint8_t     prot;
	} ph = { src,dst,0,prot };
	uint32_t cksum = l4_sum_part((uint16_t*)&ph,0,sizeof(ph));
	cksum = (cksum>>16) + (cksum&0xffff);
	cksum = (cksum>>16) + (cksum&0xffff);
	return cksum_cast(cksum);
}

uint16_t fastnet_ip4_checksum(odp_packet_t pkt,ipv4_addr_t src,ipv4_addr_t dst,uint8_t prot){
	uint32_t offset,length,checksum;
	struct ODP_PACKED
	{
		ipv4_addr_t src;
		ipv4_addr_t dst;
		uint8_t     pad0;
		uint8_t     prot;
		uint16_t    length;
	} pseudo_header;
	
	offset = odp_packet_l4_offset(pkt);
	length = odp_packet_len(pkt);
	length -= offset;
	
	pseudo_header.src     = src;
	pseudo_header.dst     = dst;
	pseudo_header.length  = odp_cpu_to_be_16(cksum_cast(length));
	pseudo_header.pad0    = 0;
	pseudo_header.prot    = prot;
	checksum = l4_sum_part((uint16_t*)(&pseudo_header),0,sizeof(pseudo_header)/2);
	return fastnet_checksum(pkt,offset,checksum,NULL,0);
}

uint16_t fastnet_ip6_checksum(odp_packet_t pkt,ipv6_addr_t src,ipv6_addr_t dst,uint8_t prot){
	uint32_t offset,length,checksum;
	struct ODP_PACKED
	{
		ipv6_addr_t src;
		ipv6_addr_t dst;
		uint32_t    length;
		uint8_t     pad0[3];
		uint8_t     prot;
	} pseudo_header;
	
	offset = odp_packet_l4_offset(pkt);
	length = odp_packet_len(pkt);
	length -= offset;
	
	pseudo_header.src     = src;
	pseudo_header.dst     = dst;
	pseudo_header.length  = odp_cpu_to_be_32(length);
	pseudo_header.pad0[0] = 0;
	pseudo_header.pad0[1] = 0;
	pseudo_header.pad0[2] = 0;
	pseudo_header.prot    = prot;
	checksum = l4_sum_part((uint16_t*)(&pseudo_header),0,sizeof(pseudo_header)/2);
	return fastnet_checksum(pkt,offset,checksum,NULL,0);
}

uint16_t fastnet_tcpudp_input_checksum(odp_packet_t pkt,uint8_t prot) {
	fnet_ip_header_t*  ip;
	fnet_ip6_header_t* ip6;
	
	if(odp_packet_has_ipv4(pkt)){
		ip = fastnet_safe_l3(pkt,sizeof(fnet_ip_header_t));
		if(odp_unlikely(ip==NULL)) return ~0;
		return fastnet_ip4_checksum(pkt, ip->source_addr, ip->destination_addr,prot);
	}else{
		ip6 = fastnet_safe_l3(pkt,sizeof(fnet_ip6_header_t));
		if(odp_unlikely(ip6==NULL)) return ~0;
		return fastnet_ip6_checksum(pkt,ip6->source_addr,ip6->destination_addr,prot);
	}
	return ~0;
}

