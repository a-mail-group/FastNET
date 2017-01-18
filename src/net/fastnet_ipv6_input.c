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
#include <net/ip6ext.h>


typedef struct ODP_PACKED {
	uint8_t next_hdr;
	uint8_t hdr_len;
} ip_hopopts_t;

typedef struct ODP_PACKED {
	uint8_t type;
	uint8_t len;
} opt_hdr_t;

enum{
	I6OPT_KEEP,
	I6OPT_DISCARD,
	I6OPT_DISCARD_ICMP,
	I6OPT_DISCARD_UICMP,
};

static int fastnet_ip6_ext_process(odp_packet_t pkt,uint32_t pos,uint32_t size){
	opt_hdr_t oh;
	uint8_t type,datalen;
	//oh = 

	while(size){
		odp_packet_copy_to_mem(pkt,pos,&oh,sizeof(oh));
		switch(oh.type){
		case FNET_IP6_OPTION_TYPE_PAD1:
			pos ++;
			size--;
			break;
		case FNET_IP6_OPTION_TYPE_PADN:
			pos += ((uint32_t)oh.len)+sizeof(oh);
			size-= ((uint32_t)oh.len)+sizeof(oh);
			break;
		/*
		 * RFC 6275  6.3.  Home Address Option:
		 * 
		 *  The Home Address option is carried by the Destination Option
		 *  extension header (Next Header value = 60).  It is used in a packet
		 *  sent by a mobile node while away from home, to inform the recipient
		 *  of the mobile node's home address.
		 * 
		 *  The Home Address option is encoded in type-length-value (TLV) format
		 *  as follows:
		 *  
		 *  Option Type
		 *    201 = 0xC9
		 *
		 *  Option Length:
		 *    8-bit unsigned integer.  Length of the option, in octets,
		 *    excluding the Option Type and Option Length fields.  This field
		 *    MUST be set to 16.
		 */
		case 0xC9:
			pos += ((uint32_t)oh.len)+sizeof(oh);
			size-= ((uint32_t)oh.len)+sizeof(oh);
			break;
		/*
		 * RFC 6788   7.  Line-Identification Option (LIO)
		 *
		 *   The Line-Identification Option (LIO) is a destination option that can
		 *   be included in IPv6 datagrams that tunnel Router Solicitation and
		 *   Router Advertisement messages.  The use of the Line-ID option in any
		 *   other IPv6 datagrams is not defined by this document.  Multiple Line-
		 *   ID destination options MUST NOT be present in the same IPv6 datagram.
		 *   The LIO has no alignment requirement.
		 *
		 *    0                   1                   2                   3
		 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 *                                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *                                   |  Option Type  | Option Length |
		 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *   | LineIDLen     |     Line ID...
		 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *
		 *                Figure 4: Line-Identification Option Layout
		 *
		 */
		case 0x8C:
			/*
			 * We recognize this option, but we cannot consume it (yet).
			 *
			 */
			pos += ((uint32_t)oh.len)+sizeof(oh);
			size-= ((uint32_t)oh.len)+sizeof(oh);
			break;
		
		/* Endpoint Identification (DEPRECATED) [[CHARLES LYNN]] */
		case 0x8A:
		/* Deprecated [RFC7731] */
		case 0x4D:
			/*
			 * We recognize this option. Skip it!
			 */
			pos += ((uint32_t)oh.len)+sizeof(oh);
			size-= ((uint32_t)oh.len)+sizeof(oh);
			break;
		
		/* RFC 7731 6.1. MPL Option */
		/*
		 * RFC 7731 6.1. MPL Option:
		 *
		 *    The MPL Option is carried in MPL Data Messages in an IPv6 Hop-by-Hop
		 *    Options header, immediately following the IPv6 header.  The MPL
		 *    Option has the following format:
		 * 
		 *       0                   1                   2                   3
		 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 *                                      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *                                      |  Option Type  |  Opt Data Len |
		 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *      | S |M|V|  rsv  |   sequence    |      seed-id (optional)       |
		 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		case 0x6D:
			/*
			 * We fundamentally understand it, but it has no effect on us.
			 */
			pos += ((uint32_t)oh.len)+sizeof(oh);
			size-= ((uint32_t)oh.len)+sizeof(oh);
			break;
		
		/*
		 * RFC 6553   3.  Format of the RPL Option
		 *
		 *      0                   1                   2                   3
		 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 *                                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *                                     |  Option Type  |  Opt Data Len |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *     |O|R|F|0|0|0|0|0| RPLInstanceID |          SenderRank           |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *     |                         (sub-TLVs)                            |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *
		 *                           Figure 1: RPL Option
		 */
		case 0x63:
			/*
			 * We fundamentally understand it, but it has no effect on us.
			 */
			pos += ((uint32_t)oh.len)+sizeof(oh);
			size-= ((uint32_t)oh.len)+sizeof(oh);
			break;
		
		/*
		 * XXX Jumbo Payload [RFC2675]
		 * case 0xC2:
		 */
		/* Unrecognized Options.*/
		default:
			/* The Option Type identifiers are internally encoded such that their
			 * highest-order two bits specify the action that must be taken if the
			 * processing IPv6 node does not recognize the Option Type.*/
			switch(>type & FNET_IP6_OPTION_TYPE_UNRECOGNIZED_MASK){
			/* 00 - skip over this option and continue processing the header.*/
			case FNET_IP6_OPTION_TYPE_UNRECOGNIZED_SKIP:
				break;
			/* 01 - discard the packet. */
			case FNET_IP6_OPTION_TYPE_UNRECOGNIZED_DISCARD:
				return I6OPT_DISCARD;
			/* 10 - discard the packet and, regardless of whether or not the
			 *      packet's Destination Address was a multicast address, send an
			 *      ICMP Parameter Problem, Code 2, message to the packet's
			 *      Source Address, pointing to the unrecognized Option Type.*/
			case FNET_IP6_OPTION_TYPE_UNRECOGNIZED_DISCARD_ICMP:
				return I6OPT_DISCARD_ICMP;
			/* 11 - discard the packet and, only if the packet's Destination
			 *      Address was not a multicast address, send an ICMP Parameter
			 *      Problem, Code 2, message to the packet's Source Address,
			 *      pointing to the unrecognized Option Type.*/
			case FNET_IP6_OPTION_TYPE_UNRECOGNIZED_DISCARD_UICMP:
				return I6OPT_DISCARD_UICMP;
			}
		}
	}
	return I6OPT_KEEP;
}

netpp_retcode_t fastnet_ip6x_hopopts(odp_packet_t pkt,int* nxt, int idx){
	ip_hopopts_t* ho;
	uint32_t size,off;
	
	(void)idx;
	
	ho = odp_packet_l4_ptr(pkt,NULL);
	
	if(odp_unlikely(ho==NULL)) return NETPP_DROP;
	
	*nxt = ho->next_hdr;
	
	
	
	size = (ho->hdr_len+1)*8;
	off = odp_packet_l4_offset(pkt);
	fastnet_ip6_ext_process(pkt,off+sizeof(ip_hopopts_t),size-sizeof(ip_hopopts_t))
	
	switch( netipv6_ext_options(netpkt_data(pkt)+2,size-2) ){
	case I6OPT_DISCARD_UICMP: // XXX: send ICMP error
	case I6OPT_DISCARD_ICMP: // XXX: send ICMP error
	case I6OPT_DISCARD:
		return NETPP_DROP;
	}
	odp_pack
	return NETPP_CONTINUE;
}

