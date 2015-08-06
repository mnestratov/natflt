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

#include "precomp.h"

#include "..\natDrvCommon\parse.c"

#define GET_NEXT_BUF(pBuf, pAddr, uLen) \
		do{ \
			NdisGetNextBuffer( pBuf, &pBuf ); \
			if (!pBuf){ \
				goto finish; \
			} \
			NdisQueryBufferSafe(pBuf, &pAddr, &uLen, NormalPagePriority); \
			if(NULL == pAddr) \
				goto finish; \
		}while(uLen == 0)


BOOLEAN
	natbParsePacket(
		IN PVOID Pkt,
		IN OUT FLT_PKT* pFltPkt
		)
{
	PNDIS_PACKET pPkt = (PNDIS_PACKET)Pkt;
	PNDIS_BUFFER pNdisBuf = NULL;
	ULONG uPktLen	= 0;
	ULONG uBufLen	= 0;
	PUCHAR pAddress = NULL;
	ULONG hlen			= 0;
	ETH_HDR* pEthHdr;
	UINT uNeedBytes	= 0;
	BOOLEAN bOk = FALSE;

	if(NULL == pPkt){

		pEthHdr = pFltPkt->pBuf;
		uBufLen = MAX_ETHER_SIZE;
		uPktLen = pFltPkt->uLen;
		pFltPkt->pData = NULL;

	}else{

		NdisGetFirstBufferFromPacketSafe(
			pPkt,
			&pNdisBuf,
			&pEthHdr,
			&uBufLen,
			&uPktLen,
			NormalPagePriority
			);
			if(NULL == pEthHdr)
				return FALSE;
		pFltPkt->pOrgPkt = pPkt;
	}

	if(uPktLen > MAX_ETHER_SIZE)
		return FALSE;
	
	if(uPktLen <  ETHERNET_HEADER_LEN + IP_HEADER_LEN)
		return FALSE;

	if(uBufLen <  ETHERNET_HEADER_LEN)
		return FALSE;

	pFltPkt->uLen = uPktLen;
	pFltPkt->pEth = pEthHdr;

	switch(pEthHdr->ether_type){
	case ETHERNET_TYPE_ARP_NET:

		if(uBufLen >= ETHERNET_HEADER_LEN + sizeof(ETH_ARP)){

			pFltPkt->pArp = (ETH_ARP*)(pFltPkt->pEth + 1);
			bOk = TRUE;
			goto finish;
		}

		if(uBufLen > ETHERNET_HEADER_LEN){

			goto finish;
		}

		GET_NEXT_BUF(pNdisBuf, pAddress, uBufLen);

		if(uBufLen < sizeof(ETH_ARP)){
			goto finish;
		}

		pFltPkt->pArp = (ETH_ARP*)(pAddress);
		bOk = TRUE;
		goto finish;
			
	case ETHERNET_TYPE_IP_NET:

		if(uBufLen >= ETHERNET_HEADER_LEN + IP_HEADER_LEN){

			pAddress = (PUCHAR)(pFltPkt->pEth + 1);

		}else if(uBufLen > ETHERNET_HEADER_LEN){

			goto finish;
		}

		uBufLen -= ETHERNET_HEADER_LEN;

		if(!uBufLen){
			
			GET_NEXT_BUF(pNdisBuf, pAddress, uBufLen);
		}

		if(uBufLen < IP_HEADER_LEN){

			goto finish;
		}
		
		if(NULL == pAddress){
			goto finish;
		}

		if(!natCheckIpHeader(
			(IP_HDR*)pAddress,
			uPktLen - ETHERNET_HEADER_LEN,
			&hlen)){

			goto finish;
		}
							
		if(hlen > uBufLen){

			goto finish;
		}
			
		pFltPkt->pIp = (IP_HDR*)pAddress;
		break;

	default:

		bOk = TRUE;
		goto finish;
	}

	uBufLen -= hlen;
	
	pAddress = (PUCHAR)pFltPkt->pIp + hlen;

	switch (pFltPkt->pIp->ip_proto){
	case IPPROTO_UDP:
		uNeedBytes = sizeof(UDP_HDR);
		break;
		
	case IPPROTO_TCP:
		uNeedBytes = sizeof(TCP_HDR);
		break;
		
	case IPPROTO_ICMP:
		uNeedBytes = uPktLen - (ETHERNET_HEADER_LEN + hlen);
		break;
		
	default:

		bOk = TRUE;
		goto finish;
	}

	if(!uBufLen){

		GET_NEXT_BUF(pNdisBuf, pAddress, uBufLen);
	}

	if(uBufLen < uNeedBytes){

		goto finish;
	}

	switch (pFltPkt->pIp->ip_proto){
	case IPPROTO_UDP:
		pFltPkt->pUdp = (UDP_HDR*)pAddress;
		uNeedBytes = RtlUshortByteSwap(pFltPkt->pUdp->uh_len) - sizeof(UDP_HDR);
		if(uNeedBytes>uPktLen){
			goto finish;
		}
		hlen = sizeof(UDP_HDR);
		pAddress = (PUCHAR)pFltPkt->pUdp + hlen;
		break;
		
	case IPPROTO_TCP:
		pFltPkt->pTcp = (TCP_HDR*)pAddress;
		uNeedBytes = uPktLen - (ETHERNET_HEADER_LEN + hlen + TCP_HDR_LEN(((TCP_HDR*)pAddress)));
		if(uNeedBytes>uPktLen){
			goto finish;
		}
		hlen = TCP_HDR_LEN(((TCP_HDR*)pAddress));
		pAddress = (PUCHAR)pFltPkt->pTcp + hlen;
		break;
		
	case IPPROTO_ICMP:
		pFltPkt->pIcmp = (ICMP_HDR*)pAddress;
		bOk = TRUE;
		goto finish;

	default:

		bOk = TRUE;
		goto finish;
	}
	
	uBufLen -= hlen;

	if(uNeedBytes && !uBufLen){

		GET_NEXT_BUF(pNdisBuf, pAddress, uBufLen);

		if(uBufLen >= uNeedBytes){

			pFltPkt->pData = (VOID*)pAddress;
			bOk = TRUE;
			goto finish;
		}
	}

	if(uBufLen < uNeedBytes){

		goto finish;
	}

	bOk = TRUE;

finish:

	if(!bOk && pPkt){

		if(CopyNdisPacketToFltPacket(pFltPkt)){
			bOk = TRUE;
		}
	}

	return bOk;
}

BOOLEAN
	natCopyPacketData(
		 IN PVOID Pkt,
		 IN OUT PUCHAR lpBuffer,
		 IN ULONG nNumberOfBytesToRead,
		 IN ULONG nOffset,                
		 IN PULONG lpNumberOfBytesRead,
		 IN BOOLEAN bWirelessWan
		 )
{
	PNDIS_PACKET Packet = (PNDIS_PACKET)Pkt;
	PNDIS_BUFFER CurrentBuffer;
	UINT nBufferCount, TotalPacketLength;
	PUCHAR VirtualAddress;
	UINT CurrentLength, CurrentOffset;
	UINT AmountToMove;

	*lpNumberOfBytesRead = 0;

	NdisQueryPacket(
		(PNDIS_PACKET )Packet,
		(PUINT )NULL,    
		(PUINT )&nBufferCount,
		&CurrentBuffer,       
		&TotalPacketLength
		);

	NdisQueryBufferSafe(
		CurrentBuffer,
		&VirtualAddress,
		&CurrentLength,
		NormalPagePriority
		);

	if ( !VirtualAddress )
		return FALSE;

	CurrentOffset = 0;

	while( nOffset || nNumberOfBytesToRead ){
		
		while( !CurrentLength ){
		
			NdisGetNextBuffer(
				CurrentBuffer,
				&CurrentBuffer
				);

			if (!CurrentBuffer)
				return TRUE;

			NdisQueryBufferSafe(
				CurrentBuffer,
				&VirtualAddress,
				&CurrentLength,
				NormalPagePriority
				);
			if ( !VirtualAddress )
				return FALSE;

			CurrentOffset = 0;
		}

		if( nOffset ){
			
			if( CurrentLength > nOffset )
				CurrentOffset = nOffset;
			else
				CurrentOffset = CurrentLength;

			nOffset -= CurrentOffset;
			CurrentLength -= CurrentOffset;
		}

		if( nOffset ) {

			CurrentLength = 0;
			continue;
		}

		if( !CurrentLength ) {
			continue;
		}

		if (CurrentLength > nNumberOfBytesToRead)
			AmountToMove = nNumberOfBytesToRead;
		else
			AmountToMove = CurrentLength;

		NdisMoveMemory(
			lpBuffer,
			&VirtualAddress[ CurrentOffset ],
			AmountToMove
			);

		lpBuffer += AmountToMove;

		*lpNumberOfBytesRead +=AmountToMove;
		nNumberOfBytesToRead -=AmountToMove;
		CurrentLength = 0;
	}

	return TRUE;
}
