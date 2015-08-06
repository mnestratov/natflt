/*
 * Copyright (C) 2015 Maxim Nestratov
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

static const char* natsState2Name(ULONG name)
{
#define STATE2STR(s) case SESSION_STATE_##s: return #s

	switch(name){
	STATE2STR(UNKNOWN);
	STATE2STR(CLOSED);
	STATE2STR(SYN_RCV);
	STATE2STR(SYN_ACK_RCV);
	STATE2STR(ESTABLISHED);
	STATE2STR(FIN_CLN_RCV);
	STATE2STR(FIN_SRV_RCV);
	default:
		break;
	}
	return "UNKNOWN";
}


void natvLogSession(
		IN const char * prefixStr,
		IN TRACED_CONNECTION* pItem,
		IN ULONG prevState,
		IN const char * sufixStr
		)
{
	TIME_FIELDS TimeFields;
	char timeStr[30];
	LARGE_INTEGER time;
	char dstIpAddrStr[30];
	char srcIpAddrStr[30];

	KeQuerySystemTime (&time);
	ExSystemTimeToLocalTime (&time, &time);
	RtlTimeToTimeFields (&time,&TimeFields);

	RtlStringCbPrintfA(timeStr, sizeof(timeStr), "%02d:%02d:%02d.%03d ",
		TimeFields.Hour, TimeFields.Minute,
		TimeFields.Second, TimeFields.Milliseconds);

	PRINT_IP(dstIpAddrStr, &pItem->dstIpAddrOrg);
	PRINT_IP(srcIpAddrStr, &pItem->srcIpAddrOrg);
	DbgPrint("%s %s session %s %s: %s:%u->%s:%u. State %s->%s\n",
		timeStr,
		prefixStr,
		pItem->out ? "OUT" : "IN ",
		sufixStr,
		srcIpAddrStr,
		RtlUshortByteSwap(pItem->srcPortOrg),
		dstIpAddrStr,
		RtlUshortByteSwap(pItem->dstPortOrg),
		natsState2Name(prevState),
		natsState2Name(pItem->state)
		);
}

VOID PrintFtlPkt(
		 IN char *strPrefix,
		 IN FLT_PKT* pFltPkt,
		 IN ULONG uNewIp,
		 IN BOOLEAN bOut
		 )
{
	TIME_FIELDS TimeFields;
	char Message[255];
	char MessagePart[30];
	LARGE_INTEGER time;

	KeQuerySystemTime (&time);
	ExSystemTimeToLocalTime (&time, &time);
	RtlTimeToTimeFields (&time,&TimeFields);

	RtlStringCbPrintfA(Message,sizeof(Message),"%02d:%02d:%02d.%03d ",
		TimeFields.Hour, TimeFields.Minute,
		TimeFields.Second, TimeFields.Milliseconds);

	if(!bOut){
		RtlStringCbCatA(Message,sizeof(Message),"IN  ");
	}else{
		RtlStringCbCatA(Message,sizeof(Message),"OUT ");
	}

	RtlStringCbCatA(Message,sizeof(Message), strPrefix);
	RtlStringCbCatA(Message,sizeof(Message), " ");

	
	if(NULL == pFltPkt->pEth){
		goto out;
	}

	RtlStringCbPrintfA (MessagePart,sizeof(MessagePart),"%02x-%02x-%02x-%02x-%02x-%02x", 
		pFltPkt->pEth->ether_src[0],
		pFltPkt->pEth->ether_src[1],
		pFltPkt->pEth->ether_src[2],
		pFltPkt->pEth->ether_src[3],
		pFltPkt->pEth->ether_src[4],
		pFltPkt->pEth->ether_src[5]);
	RtlStringCbCatA(Message,sizeof(Message),MessagePart);
	RtlStringCbCatA(Message,sizeof(Message),"->");
	RtlStringCbPrintfA (MessagePart,sizeof(MessagePart),"%02x-%02x-%02x-%02x-%02x-%02x", 
		pFltPkt->pEth->ether_dst[0],
		pFltPkt->pEth->ether_dst[1],
		pFltPkt->pEth->ether_dst[2],
		pFltPkt->pEth->ether_dst[3],
		pFltPkt->pEth->ether_dst[4],
		pFltPkt->pEth->ether_dst[5]);
	RtlStringCbCatA(Message,sizeof(Message),MessagePart);
		
	switch(pFltPkt->pEth->ether_type){
	case ETHERNET_TYPE_ARP_NET:
		RtlStringCbCatA(Message,sizeof(Message)," ARP ");

		if(NULL == pFltPkt->pArp)
			goto out;

		if(ARP_REQUEST_CODE == pFltPkt->pArp->ea_hdr.ar_op){
			RtlStringCbCatA(Message,sizeof(Message),"Request ");
		}else if(pFltPkt->pArp->ea_hdr.ar_op == ARP_REPLY_CODE){
			RtlStringCbCatA(Message,sizeof(Message),"Reply   ");	
		}

		RtlStringCbPrintfA(MessagePart,sizeof(MessagePart),"%d.%d.%d.%d",
				pFltPkt->pArp->arp_spa[0],
				pFltPkt->pArp->arp_spa[1],
				pFltPkt->pArp->arp_spa[2],
				pFltPkt->pArp->arp_spa[3]);
		RtlStringCbCatA(Message,sizeof(Message),MessagePart);

		RtlStringCbCatA(Message,sizeof(Message),"->");

		PRINT_IP(MessagePart,pFltPkt->pArp->arp_tpa);
		RtlStringCbCatA(Message,sizeof(Message),MessagePart);
		break;

	case ETHERNET_TYPE_IP_NET:

		RtlStringCbCatA(Message,sizeof(Message)," IP  ");
		
		if(NULL == pFltPkt->pIp)
			goto out;

		RtlStringCbPrintfA(MessagePart,sizeof(MessagePart),"ID %04x ",RtlUshortByteSwap(pFltPkt->pIp->ip_id));
		RtlStringCbCatA(Message,sizeof(Message),MessagePart);

		PRINT_IP(MessagePart,&pFltPkt->pIp->ip_src);
		RtlStringCbCatA(Message,sizeof(Message),MessagePart);
		if(uNewIp && bOut){
			RtlStringCbCatA(Message,sizeof(Message),"[");
			PRINT_IP(MessagePart,&uNewIp);
			RtlStringCbCatA(Message,sizeof(Message),MessagePart);
			RtlStringCbCatA(Message,sizeof(Message),"]");
		}
		RtlStringCbCatA(Message,sizeof(Message),"->");
		PRINT_IP(MessagePart,&pFltPkt->pIp->ip_dst);
		RtlStringCbCatA(Message,sizeof(Message),MessagePart);
		if(uNewIp && !bOut){
			RtlStringCbCatA(Message,sizeof(Message),"[");
			PRINT_IP(MessagePart,&uNewIp);
			RtlStringCbCatA(Message,sizeof(Message),MessagePart);
			RtlStringCbCatA(Message,sizeof(Message),"]");
		}
		
		switch(pFltPkt->pIp->ip_proto){
		case IPPROTO_TCP:
			RtlStringCbCatA(Message,sizeof(Message)," TCP");
			break;
		case IPPROTO_ICMP:
			RtlStringCbCatA(Message,sizeof(Message)," ICMP");
			break;
		case IPPROTO_UDP:
			RtlStringCbCatA(Message,sizeof(Message)," UDP");
			break;
		default:
			RtlStringCbPrintfA(MessagePart,sizeof(MessagePart)," proto=%04x", pFltPkt->pIp->ip_proto);
			RtlStringCbCatA(Message,sizeof(Message),MessagePart);
			break;
		}

		if(pFltPkt->pTcp){

			RtlStringCbPrintfA(MessagePart,sizeof(MessagePart)," %d->%d ",
				RtlUshortByteSwap(pFltPkt->pTcp->th_sport),
				RtlUshortByteSwap(pFltPkt->pTcp->th_dport));

			if(pFltPkt->pTcp->th_flags & TCP_FIN_FLAG)
				RtlStringCbCatA(MessagePart,sizeof(MessagePart),"F");	
			if(pFltPkt->pTcp->th_flags & TCP_SYN_FLAG)
				RtlStringCbCatA(MessagePart,sizeof(MessagePart),"S");	
			if(pFltPkt->pTcp->th_flags & TCP_RST_FLAG)
				RtlStringCbCatA(MessagePart,sizeof(MessagePart),"R");	
			if(pFltPkt->pTcp->th_flags & TCP_PSH_FLAG)
				RtlStringCbCatA(MessagePart,sizeof(MessagePart),"P");	
			if(pFltPkt->pTcp->th_flags & TCP_URG_FLAG)
				RtlStringCbCatA(MessagePart,sizeof(MessagePart),"U");	
			if(pFltPkt->pTcp->th_flags & TCP_ACK_FLAG)
				RtlStringCbCatA(MessagePart,sizeof(MessagePart),"A");
			// https://tools.ietf.org/html/rfc3168
			if(pFltPkt->pTcp->th_flags & TCP_ECE_FLAG)
				RtlStringCbCatA(MessagePart,sizeof(MessagePart),"E");
			if(pFltPkt->pTcp->th_flags & TCP_CWR_FLAG)
				RtlStringCbCatA(MessagePart,sizeof(MessagePart),"C");

			RtlStringCbCatA(Message,sizeof(Message),MessagePart);	

			RtlStringCbPrintfA(MessagePart,sizeof(MessagePart)," SEQ:%u",
				RtlUlongByteSwap(pFltPkt->pTcp->th_seq));

			RtlStringCbCatA(Message,sizeof(Message),MessagePart);	

			RtlStringCbPrintfA(MessagePart,sizeof(MessagePart)," ACK:%u",
				RtlUlongByteSwap(pFltPkt->pTcp->th_ack));

		}else if(pFltPkt->pUdp) {

			RtlStringCbPrintfA(MessagePart,sizeof(MessagePart)," %d->%d",
				RtlUshortByteSwap(pFltPkt->pUdp->uh_sport),
				RtlUshortByteSwap(pFltPkt->pUdp->uh_dport));

		}else if(pFltPkt->pIcmp) {

			RtlStringCbPrintfA(MessagePart,sizeof(MessagePart)," %d",
				RtlUshortByteSwap(pFltPkt->pIcmp->icmp_hun.idseq.id));
				
		}else{
			MessagePart[0] = 0;
		}
		RtlStringCbCatA(Message,sizeof(Message),MessagePart);	
		break;
	default:
		RtlStringCbPrintfA(MessagePart,sizeof(MessagePart)," UNK %04x", RtlUshortByteSwap(pFltPkt->pEth->ether_type));
		RtlStringCbCatA(Message,sizeof(Message),MessagePart);	
		break;
	}

out:
	RtlStringCbCatA(Message,sizeof(Message),"\n");

	DbgPrint(Message);
	return;
}
