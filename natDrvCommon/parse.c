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

#define MODULE_TAG1 'kP1N'
#define MODULE_TAG2 'dP1N'

NPAGED_LOOKASIDE_LIST	g_PktLookaside;
NPAGED_LOOKASIDE_LIST	g_DataLookaside;


VOID
InitPacketLookaside()
{
    ExInitializeNPagedLookasideList(
        &g_PktLookaside,
        NULL, NULL, 0,
        sizeof(FLT_PKT),
        MODULE_TAG1,
        0
    );

    ExInitializeNPagedLookasideList(
        &g_DataLookaside,
        NULL, NULL, 0,
        MAX_ETHER_SIZE,
        MODULE_TAG2,
        0
    );
}

VOID
ReleasePacketLookaside()
{
    ExDeleteNPagedLookasideList(&g_PktLookaside);
    ExDeleteNPagedLookasideList(&g_DataLookaside);
}



FORCEINLINE BOOLEAN
natCheckIpHeader(
    IN IP_HDR	*pIpHeader,
    IN ULONG	Length,
    IN PULONG	pOutLen
)
{
    ULONG			ip_len, hlen;

    *pOutLen = 0;

    if (pIpHeader->ip_ver != 4)
        return FALSE;

    hlen = pIpHeader->ip_hlen << 2;

    if (hlen < IP_HEADER_LEN)
        return FALSE;

    ip_len = RtlUshortByteSwap(pIpHeader->ip_len);

    if (ip_len > Length)
        return FALSE;

    if (ip_len != Length) {
        if (ip_len > Length || ip_len == 0)
            ip_len = Length;
    }
    if (ip_len < hlen)
        return FALSE;

    *pOutLen = hlen;

    return TRUE;
}

BOOLEAN
CopyNdisPacketToFltPacket(
    IN FLT_PKT* pFltPkt
)
{
    ULONG uReadyLen = 0;

    if (pFltPkt->pBuf)
        return TRUE;

    pFltPkt->pBuf = ExAllocateFromNPagedLookasideList(&g_DataLookaside);
    if (NULL == pFltPkt->pBuf) {
        return FALSE;
    }

    if (!natCopyPacketData(
        pFltPkt->pOrgPkt,
        (UCHAR*)pFltPkt->pBuf,
        MAX_ETHER_SIZE,
        0,
        &uReadyLen,
        FALSE
    ))
    {
        return FALSE;
    }

    if (uReadyLen != pFltPkt->uLen) {

        return FALSE;
    }

    if (!natbParsePacket(NULL, pFltPkt)) {

        return FALSE;
    }

    return TRUE;
}

FLT_PKT*
CreateFltPacketWithBuffer()
{
    FLT_PKT* pFltPkt;

    pFltPkt = AllocateFltPacket();
    if (NULL == pFltPkt)
        return NULL;

    pFltPkt->pBuf = ExAllocateFromNPagedLookasideList(&g_DataLookaside);
    if (NULL == pFltPkt->pBuf) {
        FreeFltPkt(pFltPkt);
        return NULL;
    }

    RtlZeroMemory(pFltPkt->pBuf, MAX_ETHER_SIZE);
    return pFltPkt;
}


FLT_PKT*
AllocateFltPacket()
{
    FLT_PKT* pFltPkt = (FLT_PKT*)ExAllocateFromNPagedLookasideList(&g_PktLookaside);

    if (pFltPkt)
        RtlZeroMemory(pFltPkt, sizeof(*pFltPkt));

    return pFltPkt;
}

VOID FreeFltPkt(FLT_PKT* pFltPkt)
{
    if (pFltPkt->pBuf)
        ExFreeToNPagedLookasideList(&g_DataLookaside, pFltPkt->pBuf);

    ExFreeToNPagedLookasideList(&g_PktLookaside, pFltPkt);
}

