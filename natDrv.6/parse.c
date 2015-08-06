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

BOOLEAN
	natCopyPacketData(
		 IN PVOID	Pkt,
		 IN OUT PUCHAR lpBuffer,
		 IN ULONG nBytesToRead,
		 IN ULONG nOffset,  
		 IN PULONG lpBytesRead,
		 IN BOOLEAN bWirelessWan
		 )
{
	PMDL		pMDL;
	PUCHAR	pData;
	ULONG		uBufLen;
	ULONG		uDataLen;
	IN PNET_BUFFER pNB = (PNET_BUFFER)Pkt;
	ULONG		uCurBufOffset = 0;
	ULONG		CurrentNetBufferSize = 0;

	if (pNB == NULL || lpBuffer == NULL || lpBytesRead == NULL)
		return FALSE;	
	
	*lpBytesRead = 0;

	if (nBytesToRead == 0)
		return TRUE;

	pMDL = NET_BUFFER_CURRENT_MDL(pNB);	
	CurrentNetBufferSize = NET_BUFFER_DATA_LENGTH(pNB);
	
	if(pMDL == NULL || CurrentNetBufferSize == 0){ 

		//
		// skip empty NET_BUFFER
		//
		ASSERT(FALSE);
		return FALSE;
	}

	if(bWirelessWan && 0 == nOffset){

		// Generate fake Ethernet header
		if(nBytesToRead <= ETHERNET_HEADER_LEN)
			return FALSE;

		uCurBufOffset = ETHERNET_HEADER_LEN;
		nBytesToRead -= ETHERNET_HEADER_LEN;
		RtlZeroMemory(lpBuffer, ETHERNET_HEADER_LEN);
	}

	if (MmGetMdlByteCount(pMDL) <= NET_BUFFER_CURRENT_MDL_OFFSET(pNB)){

		//
		// offset is more or equal to data size
		// NET_BUFFER seems to be invalid
		//
		ASSERT(FALSE);
		return FALSE;
	}

	uBufLen = min(CurrentNetBufferSize,
		MmGetMdlByteCount(pMDL) - NET_BUFFER_CURRENT_MDL_OFFSET(pNB));

	pData = ((PUCHAR)MmGetSystemAddressForMdlSafe(pMDL, NormalPagePriority) +
		NET_BUFFER_CURRENT_MDL_OFFSET(pNB));

	while(uBufLen && pData){

		if(CurrentNetBufferSize <= nOffset){

			//
			// requested offset is more than packet size
			//
			return FALSE;
		}

		if (0 == nOffset){
			//
			// We have reached requested offset
			//
			break;
		}

		if (nOffset >= uBufLen)
		{
			nOffset -= uBufLen;
			CurrentNetBufferSize -= uBufLen;
			uBufLen = 0;
		}
		else // nOffset < uBufLen
		{
			uBufLen -= nOffset;
			CurrentNetBufferSize -= nOffset;
			pData += nOffset;
			nOffset = 0;
			break;
		}

		if(0 == CurrentNetBufferSize){
			ASSERT(FALSE);
			return FALSE;
		}
		
		pMDL = pMDL->Next;
		if (pMDL == NULL){

			ASSERT(FALSE);
			return FALSE;
		}

		uBufLen = min(CurrentNetBufferSize,MmGetMdlByteCount(pMDL));
		pData = (PUCHAR)MmGetSystemAddressForMdlSafe(pMDL, NormalPagePriority);
		if(NULL == pData)
			return FALSE;
	}

	ASSERT(!(0 == uBufLen || NULL == pData));

	// do copy
	while (uBufLen && pData){

		uDataLen = min(nBytesToRead, uBufLen);
			
		RtlCopyMemory(lpBuffer + uCurBufOffset, pData, uDataLen);
		uCurBufOffset += uDataLen;
		nBytesToRead -= uDataLen;

		if (nBytesToRead == 0){
			//
			// finish, don't need more data
			//
			*lpBytesRead = uCurBufOffset;
			return TRUE;
		}
		uBufLen -= uDataLen;
		CurrentNetBufferSize -= uDataLen;

		if (0 == CurrentNetBufferSize){
			//
			// We have been asked to copy more data than we have
			//
			*lpBytesRead = uCurBufOffset;
			return TRUE;
		}

		pMDL = pMDL->Next;
		if (pMDL == NULL)
		{// end of MDL chain, but NET_BUFFER has more data
			return FALSE;
		}

		uBufLen = min(CurrentNetBufferSize,MmGetMdlByteCount(pMDL));
		pData = (PUCHAR)MmGetSystemAddressForMdlSafe(pMDL, NormalPagePriority);
		if(NULL == pData){
			return FALSE;
		}
	}

	return FALSE;
}



PNET_BUFFER_LIST
	filterGetNewNetBufferList(
		FLT_PKT* pFltPkt,
		PNETGW_ADAPT pFilter
		)
{
	PMDL pMDL = NULL;
	PNET_BUFFER_LIST pNBL = NULL;
	PNET_BUFFER pNB = NULL;
	ULONG uDataLength = 0, uMdlOffset = 0;
	BOOLEAN bAllocMdl = FALSE;
	FLT_PKT_CTX *pPktCtx = NULL;

	if (NULL != pFltPkt->pBuf){

		// pFltPkt contains full copy of data
		uDataLength = pFltPkt->uLen;
        pMDL = NdisAllocateMdl(pFilter->FilterHandle, pFltPkt->pBuf, pFltPkt->uLen);
        if (NULL == pMDL)
			return NULL;

		bAllocMdl = TRUE;

	}else{

		// We have original net buffer list

		ASSERT(pFltPkt->pOrgPkt);
		uDataLength = pFltPkt->uLen;
		pMDL = NET_BUFFER_CURRENT_MDL((PNET_BUFFER)pFltPkt->pOrgPkt);
		uMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET((PNET_BUFFER)pFltPkt->pOrgPkt);
		bAllocMdl = FALSE;

		if (pMDL == NULL)
			return NULL;
	}

	pNBL = NdisAllocateNetBufferAndNetBufferList(g_PoolNetBufferList, sizeof(FLT_PKT_CTX), 0, pMDL, 0, uDataLength);
	if (pNBL == NULL){
		PrintFtlPkt("NdisAllocateNetBufferAndNetBufferList ", pFltPkt, 0, !pFltPkt->Incoming);
		goto cleanup;
	}

	pPktCtx = (FLT_PKT_CTX*)NET_BUFFER_LIST_CONTEXT_DATA_START(pNBL);
	pPktCtx->Signature = 'eNwG';
	pPktCtx->Size = sizeof(FLT_PKT_CTX);
	pPktCtx->pFltPkt = pFltPkt;
	NET_BUFFER_LIST_INFO(pNBL, TcpIpChecksumNetBufferListInfo) = 0;
	NET_BUFFER_LIST_INFO(pNBL, TcpLargeSendNetBufferListInfo) = 0;
	
	pNB = NET_BUFFER_LIST_FIRST_NB(pNBL);
	NET_BUFFER_CURRENT_MDL_OFFSET(pNB) = uMdlOffset;
	NET_BUFFER_DATA_OFFSET(pNB) = uMdlOffset;
 	pNBL->SourceHandle = pFilter->FilterHandle;

	return pNBL;

cleanup:

	if (bAllocMdl){
		
		while(pMDL != NULL){
			PMDL pTempMdl;
			pTempMdl = pMDL;
			pMDL = pMDL->Next;
			NdisFreeMdl(pTempMdl);
		}
	}

	if (pNBL != NULL)
		NdisFreeNetBufferList(pNBL);

	return NULL;
}

#define GET_NEXT_MDL	do{ \
							uCurNetBufSz -= uBufLen; \
							uBufLen = 0; \
							if (0 == uCurNetBufSz){ \
								return TRUE; \
							}else{ \
								pMDL = pMDL->Next; \
								if (pMDL == NULL){ \
									return FALSE; \
								} \
								uBufLen = min(uCurNetBufSz,MmGetMdlByteCount(pMDL)); \
								pAddress = (PUCHAR)MmGetSystemAddressForMdlSafe(pMDL, NormalPagePriority); \
 								if (pAddress == NULL){ \
									return FALSE; \
								} \
							} \
						}while(uBufLen == 0);

#define GOTO_FINISH { \
			goto finish; \
		}

BOOLEAN
	natbParsePacket(
		IN PVOID Pkt,
		IN OUT FLT_PKT* pFltPkt
		)
{
	PNET_BUFFER pNetBuf = (PNET_BUFFER)Pkt;
	ULONG uPktLen	= 0;
	ULONG uBufLen	= 0;
	ULONG uCurNetBufSz = 0;
	PUCHAR pAddress = NULL;
	ULONG hlen = 0;
	ETH_HDR* pEthHdr;
	UINT uNeedBytes	= 0;
	PMDL pMDL = NULL;
	PVOID p;

	if(NULL == pNetBuf){

		pEthHdr = pFltPkt->pBuf;
		uBufLen = MAX_ETHER_SIZE;
		uPktLen = pFltPkt->uLen;
		pFltPkt->pData = NULL;

	}else{
		
		uPktLen = NET_BUFFER_DATA_LENGTH(pNetBuf);
		pFltPkt->pOrgPkt = pNetBuf;

		pFltPkt->uLen = uPktLen;
		uCurNetBufSz = NET_BUFFER_DATA_LENGTH(pNetBuf);
		pMDL = NET_BUFFER_CURRENT_MDL(pNetBuf);

		if (MmGetMdlByteCount(pMDL) <= NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuf))
			goto finish;

		uBufLen = min(MmGetMdlByteCount(pMDL) - NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuf), uCurNetBufSz);
		p = MmGetSystemAddressForMdlSafe(pMDL, NormalPagePriority);
		if (p == NULL)
			GOTO_FINISH;

		pEthHdr = (ETH_HDR*)((PUCHAR)p + NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuf));
	}

	pFltPkt->pEth = pEthHdr;

	switch(pEthHdr->ether_type){
	case ETHERNET_TYPE_ARP_NET:

		if (uBufLen >= ETHERNET_HEADER_LEN + sizeof(ETH_ARP)){
			pFltPkt->pArp = (ETH_ARP*)(pFltPkt->pEth + 1);
			return TRUE;
		}

		if (uBufLen > ETHERNET_HEADER_LEN)
			GOTO_FINISH;

		GET_NEXT_MDL;

		if (uBufLen < sizeof(ETH_ARP))
			GOTO_FINISH;

		pFltPkt->pArp = (ETH_ARP*)(pAddress);
		return TRUE;

	case ETHERNET_TYPE_IP_NET:
	{
		hlen = IP_HEADER_LEN;

		if (uBufLen >= ETHERNET_HEADER_LEN + hlen){

			uBufLen -= ETHERNET_HEADER_LEN;			
			pAddress = (PUCHAR)(pFltPkt->pEth + 1);

		}else if(uBufLen > ETHERNET_HEADER_LEN){

			GOTO_FINISH;

		}else{

			GET_NEXT_MDL;
		}

		if(uBufLen < hlen)
			GOTO_FINISH;
		
		if(pAddress == NULL)
			GOTO_FINISH;

		if(!natCheckIpHeader(
							(IP_HDR*)pAddress,
							uPktLen - ETHERNET_HEADER_LEN,
							&hlen))
			GOTO_FINISH;

		if(hlen > uBufLen)
			GOTO_FINISH;

		pFltPkt->pIp = (IP_HDR*)pAddress;
	}
		break;

	default:
		return TRUE;
	}

	uBufLen -= hlen;
	uCurNetBufSz -= hlen;
	
	pAddress = pAddress + hlen;

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
	case IPV6_ICMPV6_PROTO:
		uNeedBytes = uPktLen - (ETHERNET_HEADER_LEN + hlen);
		break;
		
	default:
		return TRUE;
	}

	if(uBufLen == 0){

		GET_NEXT_MDL;
	}

	if (uBufLen < uNeedBytes)
		GOTO_FINISH;

	switch (pFltPkt->pIp->ip_proto){
	case IPPROTO_UDP:
		pFltPkt->pUdp = (UDP_HDR*)pAddress;
		uNeedBytes = ntohs(pFltPkt->pUdp->uh_len) - sizeof(UDP_HDR);
		if(uNeedBytes > uPktLen)
			goto finish;
		hlen = sizeof(UDP_HDR);
		pAddress = (PUCHAR)pFltPkt->pUdp + hlen;
		break;
		
	case IPPROTO_TCP:
		pFltPkt->pTcp = (TCP_HDR*)pAddress;
		uNeedBytes = uPktLen - (ETHERNET_HEADER_LEN + hlen + TCP_HDR_LEN(((TCP_HDR*)pAddress)));
		if(uNeedBytes > uPktLen)
			goto finish;
		hlen = TCP_HDR_LEN(((TCP_HDR*)pAddress));
		pAddress = (PUCHAR)pFltPkt->pTcp + hlen;
		break;
		
	case IPPROTO_ICMP:
		pFltPkt->pIcmp = (ICMP_HDR*)pAddress;
		hlen = sizeof(ICMP_HDR);
		pAddress = (PUCHAR)pFltPkt->pIcmp + hlen;
		break;
	default:
		GOTO_FINISH;
	}

	if(hlen > uBufLen)
		GOTO_FINISH;

	uBufLen -= hlen;
	uCurNetBufSz -= hlen;

	if (uNeedBytes && uBufLen == 0){

		GET_NEXT_MDL;

		if(uBufLen >= uNeedBytes){
			pFltPkt->pData = (VOID UNALIGNED*)pAddress;
			return TRUE;
		}
	}

	if(uBufLen < uNeedBytes)
		GOTO_FINISH;

	// data is placed within the same buffer as transport header
	pFltPkt->pData = NULL;
	return TRUE;

finish:

	if(pNetBuf)
		return CopyNdisPacketToFltPacket(pFltPkt);

	return FALSE;
}
