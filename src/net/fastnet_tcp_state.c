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
#include <net/nif.h>
#include <net/types.h>
#include <net/_config.h>
#include <net/header/tcphdr.h>
#include <net/safe_packet.h>
#include <net/socket_tcp.h>
#include <net/fastnet_tcp.h>
#include <net/header/layer4.h>
#include <net/checksum.h>
#include <net/net_tcp_seqnums.h>

#define NOBODY { return NETPP_DROP; }

/*-------------------------------------------*/

enum {
	SIG_CONNECTION_REFUSED,
	SIG_CONNECTION_RESET,
	SIG_CONNECTION_CLOSING,
	SIG_INTERRUPT,
};

static
void fastnet_socket_tcp_signal(fastnet_socket_t pkt,int signal) {}

/*-------------------------------------------*/

struct seg_info{
	uint32_t seq;
	uint32_t ack;
	uint32_t wnd;
	uint32_t urg;
	uint32_t flags;
	uint32_t header_len;
	uint32_t len;
};

static inline
void fastnet_tcp_seg_info(fnet_tcp_header_t* th,struct seg_info * __restrict__ seg,uint32_t len) {
	seg->seq = odp_be_to_cpu_32(th->sequence_number);
	seg->ack = odp_be_to_cpu_32(th->ack_number);
	seg->wnd = odp_be_to_cpu_16(th->window);
	seg->urg = odp_be_to_cpu_32(th->urgent_ptr);
	seg->flags = odp_be_to_cpu_16(th->hdrlength__flags);
	seg->header_len = (seg->flags&0xF000)>>10; /* (FLAGS>>12)*4 */
	seg->len = len - seg->header_len;
}

static netpp_retcode_t fastnet_tcp_closed (odp_packet_t pkt,socket_key_t *key,fastnet_socket_t sock) NOBODY
static netpp_retcode_t fastnet_tcp_synsent(odp_packet_t pkt,socket_key_t *key,fastnet_socket_t sock) NOBODY

static netpp_retcode_t fastnet_tcp_seqcheck(struct seg_info * __restrict__ seg,fastnet_tcp_pcb_t* __restrict__ pcb) {
	uint32_t end_win;
	uint32_t end_seg;
	/*
	 * RFC-793:
	 *
	 * Segment Receive  Test
	 * Length  Window
	 * ------- -------  -------------------------------------------
	 * 
	 *    0       0     SEG.SEQ = RCV.NXT
	 * 
	 *    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
	 * 
	 *   >0       0     not acceptable
	 * 
	 *   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
	 *               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
	 */
	
	/*
	 * Unifications:
	 * 
	 * ( SEG.SEQ = RCV.NXT )  <==>  ( RCV.NXT =< SEG.SEQ < RCV.NXT+1 )
	 */
	if(seg->len) end_seg = seg->seq + seg->len - 1; /* SEG.SEQ+SEG.LEN-1 */
	else         end_seg = seg->seq;
	
	if(pcb->rcv.wnd){
		end_win = pcb->rcv.nxt + pcb->rcv.wnd;
	}else{
		if(odp_unlikely(seg->len>0)) return NETPP_DROP; /* not acceptable */
		end_win = pcb->rcv.nxt + 1;
	}
	
	if(	( TCPSEQ_IS_LOWER_EQ(pcb->rcv.nxt,seg->seq) && TCPSEQ_IS_LOWER(seg->seq, end_win) ) ||
		( TCPSEQ_IS_LOWER_EQ(pcb->rcv.nxt,end_seg ) && TCPSEQ_IS_LOWER(end_seg , end_win) ) ){
		return NETPP_CONTINUE;
	}
	return NETPP_DROP;
}

netpp_retcode_t fastnet_tcp_process(odp_packet_t pkt,socket_key_t *key,fastnet_socket_t sock){
	netpp_retcode_t ret = NETPP_DROP;
	fastnet_tcp_pcb_t* pcb = odp_buffer_addr(sock);
	fnet_tcp_header_t* th;
	//uint16_t flags;
	uint32_t payload_length;
	struct seg_info seg;
	
	switch(pcb->state){
	case CLOSED:
		return fastnet_tcp_closed(pkt,key,sock);
	case LISTEN:
		return fastnet_tcp_handshake_listen(pkt,key,sock);
	case SYN_SENT:
		return fastnet_tcp_synsent(pkt,key,sock);
	}
	
	th = fastnet_safe_l4(pkt,sizeof(fnet_tcp_header_t));
	if(odp_unlikely(th==NULL)) return NETPP_DROP;
	
	fastnet_tcp_seg_info(th,&seg,odp_packet_len(pkt)-odp_packet_l4_offset(pkt));
	
	//flags = seg.flags;
	
	/*
	 * RFC-793   [Page 68]
	 *
	 * Otherwise,
	 *
	 * first check sequence number
	 */
	ret = fastnet_tcp_seqcheck(&seg,pcb);
	if(odp_unlikely(ret!=NETPP_CONTINUE)) return ret;
	
	
	
	/*
	 * second check the RST bit
	 *
	 * If the RST bit is set, THEN....
	 */
	if(odp_unlikely( seg.flags & FNET_TCP_SGT_RST) ){
		switch(pcb->state){
		case SYN_RECEIVED:
			/*
			 * If this connection was initiated with a passive OPEN (i.e.,
			 * came from the LISTEN state), then return this connection to
			 * LISTEN state and return.  The user need not be informed.  If
			 * this connection was initiated with an active OPEN (i.e., came
			 * from SYN-SENT state) then the connection was refused, signal
			 * the user "connection refused".  In either case, all segments
			 * on the retransmission queue should be removed.  And in the
			 * active OPEN case, enter the CLOSED state and delete the TCB,
			 * and return.
			 */
			pcb->state = CLOSED;
			fastnet_socket_tcp_signal(sock,SIG_CONNECTION_REFUSED);
			break;
		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
			/*
			 * any outstanding RECEIVEs and SEND
			 * should receive "reset" responses.  All segment queues should be
			 * flushed.  Users should also receive an unsolicited general
			 * "connection reset" signal.  Enter the CLOSED state, delete the
			 * TCB, and return.
			 */
			pcb->state = CLOSED;
			fastnet_socket_tcp_signal(sock,SIG_CONNECTION_RESET);
			break;
		default:
			/*
			 * CLOSING STATE
			 * LAST-ACK STATE
			 * TIME-WAIT
			 *
			 * If the RST bit is set then, enter the CLOSED state, delete the
			 * TCB, and return.
			 */
			pcb->state = CLOSED;
			fastnet_socket_tcp_signal(sock,SIG_INTERRUPT);
		}
		/* Remove socket from socket table. */
		fastnet_socket_remove(sock);
		return NETPP_DROP;
	}
	
	/* third check security and precedence (LATER) */
	
	/* fourth, check the SYN bit */
	if(odp_unlikely( seg.flags & FNET_TCP_SGT_SYN) ) {
		/*
		 * If the SYN is in the window it is an error, send a reset, any
		 * outstanding RECEIVEs and SEND should receive "reset" responses,
		 * all segment queues should be flushed, the user should also
		 * receive an unsolicited general "connection reset" signal, enter
		 * the CLOSED state, delete the TCB, and return.
		 *
		 * If the SYN is not in the window this step would not be reached
		 * and an ack would have been sent in the first step (sequence
		 * number check).
		 */
		pcb->state = CLOSED;
		fastnet_socket_tcp_signal(sock,SIG_CONNECTION_RESET);
		
		/*
		 * Remove socket from socket table.
		 */
		fastnet_socket_remove(sock);
		return NETPP_DROP;
	}
	
	/*
	 * fifth check the ACK field
	 *
	 * if the ACK bit is on...
	 */
	if(odp_likely( !!(seg.flags & FNET_TCP_SGT_ACK) ))
	switch(pcb->state){
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
	case CLOSING:
		/*
		 * If the ACK acks
		 * something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
		 * drop the segment, and return.
		 */
		if(TCPSEQ_IS_LOWER(pcb->snd.nxt,seg.ack)){
			/* XXX RFC-793 Says: "Send ACK"  ack-Number = ? */
			return fastnet_tcp_output_flags(pkt,key,
				/*SEQ=*/ pcb->rcv.nxt,
				/*ACK=*/ pcb->snd.nxt,
				FNET_TCP_SGT_ACK
			);
		}
		
		/*
		 * If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be ignored.
		 */
		if(TCPSEQ_IS_LOWER(seg.ack,pcb->snd.una)) break;
		
		/*
		 * If SND.UNA < SEG.ACK =< SND.NXT then...
		 */
		if( TCPSEQ_IS_LOWER_EQ(seg.ack,pcb->snd.nxt) ){
			/*
			 * ... set SND.UNA <- SEG.ACK.
			 * Any segments on the retransmission queue which are thereby
			 * entirely acknowledged are removed.
			 */
			pcb->snd.una = seg.ack;
			/* TODO flush output queue. */
			
			/*
			 * the send window should be
			 * updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
			 * SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
			 * SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
			 */
			if(	TCPSEQ_IS_LOWER(pcb->snd.wl1,seg.seq) ||
				( ((pcb->snd.wl1)==seg.seq) && TCPSEQ_IS_LOWER(pcb->snd.wl2,seg.ack))) {
				pcb->snd.wnd = seg.wnd;
				pcb->snd.wl1 = seg.seq;
				pcb->snd.wl2 = seg.ack;
			}
			
			switch(pcb->state){
			case FIN_WAIT_1:
				/*
				 * In addition to the processing for the ESTABLISHED state, if
				 * our FIN is now acknowledged then enter FIN-WAIT-2 and continue
				 * processing in that state.
				 */
				/* XXX */
				pcb->state = FIN_WAIT_2;
				break;
			case FIN_WAIT_2:
				/*
				 * In addition to the processing for the ESTABLISHED state, if
				 * the retransmission queue is empty, the user's CLOSE can be
				 * acknowledged ("ok") but do not delete the TCB.
				 */
				/* TODO */
				break;
			case CLOSING:
				/*
				 * In addition to the processing for the ESTABLISHED state, if
				 * the ACK acknowledges our FIN then enter the TIME-WAIT state,
				 * otherwise ignore the segment.
				 */
				/* XXX */
				pcb->state = TIME_WAIT;
				break;
			}
			break;
		}
		break;
	case LAST_ACK:
		/*
		 * The only thing that can arrive in this state is an
		 * acknowledgment of our FIN.  If our FIN is now acknowledged,
		 * delete the TCB, enter the CLOSED state, and return.
		 */
		/* XXX */
		pcb->state = CLOSED;
		/* TODO */
		break;
	case TIME_WAIT:
		/*
		 * The only thing that can arrive in this state is a
		 * retransmission of the remote FIN.  Acknowledge it, and restart
		 * the 2 MSL timeout.
		 */
		/* TODO */
		break;
	}
	/*
	 * if the ACK bit is off drop the segment and return
	 *
	 * ERRETUM: let Packets with FIN=1 and ACK=0 pass.
	 */
	else if(odp_unlikely(!( seg.flags & FNET_TCP_SGT_FIN  )) ) return NETPP_DROP;
	
	
	/* sixth, check the URG bit (LATER) */
	
	/* seventh, process the segment text */
	switch(pcb->state){
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
		/* TODO: */
		break;

	}
	
	/* eighth, check the FIN bit, */
	
	if(odp_unlikely( seg.flags & FNET_TCP_SGT_FIN) ) {
		/* TODO: sequence and ack number for FIN-ACK */
		if(ret!=NETPP_CONSUMED)
			ret = fastnet_tcp_output_flags(pkt,key,0,0,FNET_TCP_SGT_FIN|FNET_TCP_SGT_ACK);
		else
			fastnet_tcp_output_flags(ODP_PACKET_INVALID,key,0,0,FNET_TCP_SGT_FIN|FNET_TCP_SGT_ACK);
		
		switch(pcb->state){
		case SYN_RECEIVED:
		case ESTABLISHED:
			pcb->state = CLOSE_WAIT;
			break;
		case FIN_WAIT_1:
			if(seg.flags & FNET_TCP_SGT_ACK) pcb->state = TIME_WAIT;
			else                             pcb->state = CLOSING;
			break;
		case FIN_WAIT_2:
			pcb->state = TIME_WAIT;
			break;
		/*
		 * Remain:
		 *   CLOSE-WAIT
		 *   CLOSING
		 *   LAST-ACK
		 *   TIME-WAIT
		 */
		}
		fastnet_socket_tcp_signal(sock,SIG_CONNECTION_CLOSING);
	}
	return ret;
}

