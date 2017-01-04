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

KTIMER g_TracedTimer;
KDPC g_TracedDpc;

LIST_ENTRY g_TracedList;
NDIS_SPIN_LOCK g_TracedSpinLock;

static VOID
RecalcChecksums(
    IN OUT FLT_PKT* pFltPkt
);

static VOID
ProcessTraced(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN NAT_ENTRY *pItem,
    IN ULONG newIpAddr,
    IN OUT FLT_PKT* pFltPkt,
    IN BOOLEAN bOut
);

static VOID
TracedTimerFunction(
    IN struct _KDPC *Dpc,
    IN PVOID DeferredContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
);

static VOID
natReleaseTracedSingle(
    IN NAT_ENTRY *pNatItem
);


VOID natInitTraced()
{
    LARGE_INTEGER DueTime;

    KeInitializeTimer(&g_TracedTimer);

    KeInitializeDpc(&g_TracedDpc, TracedTimerFunction, NULL);

    InitializeListHead(&g_TracedList);
    NdisAllocateSpinLock(&g_TracedSpinLock);

    DueTime.QuadPart = -1;
    KeSetTimerEx(&g_TracedTimer, DueTime, INIT_SESSION_TIMEOUT_SEC * 1000, &g_TracedDpc);
}

VOID
natReleaseTracedAll()
{
    KeCancelTimer(&g_TracedTimer);
    KeFlushQueuedDpcs();
}


VOID
natReleaseTracedSingle(
    IN NAT_ENTRY *pNatItem
)
{
    PLIST_ENTRY pListEntry;
    TRACED_CONNECTION *pItem;

    NdisAcquireSpinLock(&g_TracedSpinLock);

    for (pListEntry = g_TracedList.Flink; pListEntry != &g_TracedList;) {

        pItem = CONTAINING_RECORD(pListEntry, TRACED_CONNECTION, GlobalEntry);

        ASSERT(pItem->pNatItem);

        pListEntry = g_TracedList.Flink;

        if (pNatItem != pItem->pNatItem) {

            continue;
        }

        RemoveEntryList(&pItem->GlobalEntry);
    }

    NdisReleaseSpinLock(&g_TracedSpinLock);
}

static VOID
natInitHashTable(
    IN NAT_HASH_TABLE *pHash
)
{
    int i;

    for (i = 0; i < NAT_HASH_TBL_SZ; i++) {

        InitializeListHead(pHash->List + i);
        NdisAllocateSpinLock(pHash->Locks + i);
    }
}

static VOID
natFreeHashtable(NAT_HASH_TABLE *pHash)
{
    int i;

    for (i = 0; i < NAT_HASH_TBL_SZ; i++) {

        NdisFreeSpinLock(pHash->Locks + i);
    }
}

void natInitControlBlock(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapt
)
{
    UINT i;

    InitializeListHead(&pAdapt->TcpRuleList);
    NdisAllocateSpinLock(&pAdapt->TcpRuleLock);

    InitializeListHead(&pAdapt->UdpRuleList);
    NdisAllocateSpinLock(&pAdapt->UdpRuleLock);

    InitializeListHead(&pAdapt->IcmpRuleList);
    NdisAllocateSpinLock(&pAdapt->IcmpRuleLock);

    for (i = 0; i < FLT_FW_SESSION_HASH_TBL_SZ; i++) {
        NdisAllocateSpinLock(pAdapt->FwSessionLocks + i);
        InitializeListHead(pAdapt->FwSessionList + i);
    }

    natInitHashTable(&pAdapt->NatIncoming);
    natInitHashTable(&pAdapt->NatOutgoing);
}

VOID
natInsertEntry(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN NAT_ENTRY *pItem
)
{
    ULONG uHashIndex;
    LIST_ENTRY *pList;
    NDIS_SPIN_LOCK *pLock;
    char prvAddr[30];
    char pubAddr[30];
    FLT_PKT* pArpPkt;
    NDIS_STATUS Status;

    NdisAllocateSpinLock(&pItem->Lock);
    InitializeListHead(&pItem->TracedList);

    PRINT_IP(prvAddr, &pItem->prvIpAddr);
    PRINT_IP(pubAddr, &pItem->pubIpAddr);
    DbgPrint("NAT entry: prv=%s pub=%s \n", prvAddr, pubAddr);

    uHashIndex = NAT_HASH_VALUE(pItem->prvIpAddr);
    pList = pAdapter->NatOutgoing.List + uHashIndex;
    pLock = pAdapter->NatOutgoing.Locks + uHashIndex;
    NdisAcquireSpinLock(pLock);
    InsertHeadList(pList, &pItem->OutEntry);
    NdisReleaseSpinLock(pLock);

    uHashIndex = NAT_HASH_VALUE(pItem->pubIpAddr);
    pList = pAdapter->NatIncoming.List + uHashIndex;
    pLock = pAdapter->NatIncoming.Locks + uHashIndex;
    NdisAcquireSpinLock(pLock);
    InsertHeadList(pList, &pItem->InEntry);
    NdisReleaseSpinLock(pLock);

    // Now deal with potential ARP cache problem
    // that can occur in case other devices on the network
    // have long timeouts for their ARP cache entries.
    pArpPkt = CreateFltPacketWithBuffer();

    pArpPkt->pEth = (ETH_HDR *)(pArpPkt->pBuf);
    pArpPkt->pArp = (ETH_ARP *)(pArpPkt->pEth + 1);

    // ETHERNET HEADER
    ETH_COPY_NETWORK_ADDRESS(pArpPkt->pEth->ether_src, pAdapter->MacAddr.Arr);
    RtlFillMemory(pArpPkt->pEth->ether_dst, 6, -1);
    pArpPkt->pEth->ether_type = ETHERNET_TYPE_ARP_NET;

    // ARP HEADER
    RtlZeroMemory(pArpPkt->pArp->arp_tha, 6);
    *(ULONG*)pArpPkt->pArp->arp_tpa = pItem->pubIpAddr;
    ETH_COPY_NETWORK_ADDRESS(pArpPkt->pArp->arp_sha, pAdapter->MacAddr.Arr);
    *(ULONG*)pArpPkt->pArp->arp_spa = pItem->pubIpAddr;
    pArpPkt->pArp->ea_hdr.ar_hrd = 0x0100; // ETHERNET
    pArpPkt->pArp->ea_hdr.ar_pro = 0x0008; // IP
    pArpPkt->pArp->ea_hdr.ar_op = 0x0100;  // REQUEST
    pArpPkt->pArp->ea_hdr.ar_pln = sizeof(pArpPkt->pArp->arp_spa);
    pArpPkt->pArp->ea_hdr.ar_hln = sizeof(pArpPkt->pArp->arp_tha);

    pArpPkt->uLen = sizeof(ETH_HDR) + sizeof(ETH_ARP);

    Status = natmSendFltPacket(pAdapter, pArpPkt);
    DbgPrint("NAT entry: ARP announce for IP=%s sending %s\n",
        pubAddr,
        NDIS_STATUS_SUCCESS == Status ? "SUCCEEDED" : "FAILED");
}

VOID
natFreeAllItems(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter
)
{
    ULONG i, uHashIndex;
    LIST_ENTRY *pListOut;
    NDIS_SPIN_LOCK *pLockOut;
    LIST_ENTRY *pListIn;
    NDIS_SPIN_LOCK *pLockIn;
    LIST_ENTRY *pEntry;
    NAT_ENTRY *pItem;

    for (i = 0; i < NAT_HASH_TBL_SZ; i++) {

        pListOut = pAdapter->NatOutgoing.List + i;
        pLockOut = pAdapter->NatOutgoing.Locks + i;
        NdisAcquireSpinLock(pLockOut);

        while (!IsListEmpty(pListOut)) {

            pEntry = RemoveHeadList(pListOut);

            pItem = CONTAINING_RECORD(pEntry, NAT_ENTRY, OutEntry);

            uHashIndex = NAT_HASH_VALUE(pItem->pubIpAddr);
            pLockIn = pAdapter->NatIncoming.Locks + uHashIndex;
            NdisAcquireSpinLock(pLockIn);
            RemoveEntryList(&pItem->InEntry);
            NdisReleaseSpinLock(pLockIn);

            natReleaseTracedSingle(pItem);

            NdisAcquireSpinLock(&pItem->Lock);
            while (!IsListEmpty(&pItem->TracedList)) {

                TRACED_CONNECTION *pTraced;

                pEntry = RemoveHeadList(&pItem->TracedList);

                pTraced = CONTAINING_RECORD(pEntry, TRACED_CONNECTION, ListEntry);

                ExFreePool(pTraced);
            }
            NdisReleaseSpinLock(&pItem->Lock);

            ExFreePool(pItem);
        }

        NdisReleaseSpinLock(pLockOut);
    }

    for (i = 0; i < NAT_HASH_TBL_SZ; i++) {

        pListIn = pAdapter->NatIncoming.List + i;
        ASSERT(IsListEmpty(pListIn));
    }

    natFreeHashtable(&pAdapter->NatIncoming);
    natFreeHashtable(&pAdapter->NatOutgoing);

}

BOOLEAN
TranslatePktIncoming(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN OUT FLT_PKT* pFltPkt
)
{
    BOOLEAN bFound = FALSE;
    LIST_ENTRY *pBucket;
    LIST_ENTRY *pEntry;
    NDIS_SPIN_LOCK *pLock;
    NAT_ENTRY *pItem = NULL;
    ULONG uHashIndex;
    ULONG uKeyAddr;

    if (!pAdapter->bFiltered)
        return FALSE;

    if (NULL == pFltPkt->pIp)
        return FALSE;

    uKeyAddr = pFltPkt->pIp->ip_dst;
    uHashIndex = NAT_HASH_VALUE(uKeyAddr);

    pBucket = pAdapter->NatIncoming.List + uHashIndex;
    pLock = pAdapter->NatIncoming.Locks + uHashIndex;

    NdisAcquireSpinLock(pLock);

    for (pEntry = pBucket->Flink; pEntry != pBucket; pEntry = pEntry->Flink) {

        pItem = (NAT_ENTRY*)CONTAINING_RECORD(pEntry, NAT_ENTRY, InEntry);

        if (uKeyAddr == pItem->pubIpAddr) {

            bFound = TRUE;
            break;
        }

    }// for(...

    NdisReleaseSpinLock(pLock);

    if (bFound) {

        ProcessTraced(pAdapter, pItem, pItem->prvIpAddr, pFltPkt, FALSE);

        if (g_LogPktNAT) PrintFtlPkt("NATed", pFltPkt, pItem->prvIpAddr, FALSE);

        pFltPkt->pIp->ip_dst = pItem->prvIpAddr;

        RecalcChecksums(pFltPkt);
    }

    return bFound;
}

BOOLEAN
TranslatePktOutgoing(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN OUT FLT_PKT* pFltPkt
)
{
    BOOLEAN bFound = FALSE;
    LIST_ENTRY *pBucket;
    LIST_ENTRY *pEntry;
    NDIS_SPIN_LOCK *pLock;
    NAT_ENTRY *pItem = NULL;
    ULONG uHashIndex;
    ULONG uKeyAddr;

    if (!pAdapter->bFiltered)
        return FALSE;

    if (NULL == pFltPkt->pIp)
        return FALSE;

    uKeyAddr = pFltPkt->pIp->ip_src;
    uHashIndex = NAT_HASH_VALUE(uKeyAddr);

    pBucket = pAdapter->NatOutgoing.List + uHashIndex;
    pLock = pAdapter->NatOutgoing.Locks + uHashIndex;

    NdisAcquireSpinLock(pLock);

    for (pEntry = pBucket->Flink; pEntry != pBucket; pEntry = pEntry->Flink) {

        pItem = (NAT_ENTRY*)CONTAINING_RECORD(pEntry, NAT_ENTRY, OutEntry);

        if (uKeyAddr == pItem->prvIpAddr) {

            bFound = TRUE;
            break;
        }

    }// for(...

    NdisReleaseSpinLock(pLock);

    if (bFound) {

        ProcessTraced(pAdapter, pItem, pItem->pubIpAddr, pFltPkt, TRUE);

        if (g_LogPktNAT) PrintFtlPkt("NATed", pFltPkt, pItem->pubIpAddr, TRUE);

        pFltPkt->pIp->ip_src = pItem->pubIpAddr;

        RecalcChecksums(pFltPkt);
    }

    return bFound;
}

static ULONG tens[5] =
{
    1,
    10,
    100,
    1000,
    10000,
};

static ULONG NatAtoi(char *Str)
{
    ULONG result = 0;
    ULONG Numbers[5];
    int i;
    int digits;

    for (i = 0; i < 5; i++) {

        if (0 == Str[i])
            break;

        if ('0' > Str[i] || Str[i] > '9')
            break;

        Numbers[i] = Str[i] - '0';
    }

    digits = i - 1;
    if (0 == i)
        return 0;

    for (i = digits; i >= 0; i--) {

        result += Numbers[i] * tens[digits - i];
    }

    return result;
}

static int natFixFtpPortContentAndCreateFwSession(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN OUT FLT_PKT* pFltPkt,
    IN ULONG newIpAddr,
    IN BOOLEAN bDoModify,
    IN BOOLEAN bOut
)
{
    int diff = 0;
    char * data, *new_data;
    ULONG sample_len = sizeof("PORT ") - 1;
    ULONG org_addr_len, i;
    size_t new_addr_len;
    ULONG addr[6] = { 0 };
    unsigned char *new_addr_ptr = (unsigned char*)&newIpAddr;
    char new_port_str[] = "PORT 255,255,255,255,255,255  ";
    char *c;
    ULONG tcp_data_len = pFltPkt->uLen - ETHERNET_HEADER_LEN - IP_HDR_LEN(pFltPkt->pIp) - TCP_HDR_LEN(pFltPkt->pTcp);

    if (tcp_data_len > MAX_ETHER_SIZE)
        return 0;

    if (pFltPkt->pData)
        data = (char*)pFltPkt->pData;
    else
        data = (char*)pFltPkt->pTcp + TCP_HDR_LEN(pFltPkt->pTcp);

    if (_strnicmp("PORT ", data, sample_len)) {

        //
        // substring was not found - nothing to do
        //
        return 0;
    }

    //
    // try to find the end of port command
    //
    c = strchr(data, 0xa);

    org_addr_len = (ULONG)(ULONG_PTR)(c - data + 1);
    if (NULL == c || org_addr_len > tcp_data_len || 0xd != c[-1]) {
        //
        // invalid format
        //
        return 0;
    }

    //
    // get IP address and port
    //
    c = data + sample_len;

    i = 0;

    while (i < 6) {
        addr[i] = NatAtoi(c);
        c = strchr(c, ',');
        if (NULL == c) {
            if (i != 5)
                return 0;
            break;
        }
        i++;
        c++;
    }

    //
    // Here we create firewall session
    // to allow active FTP to work correctly
    //

    if (!natbFwSessionCreate(
        pAdapter,
        bOut ? pFltPkt->pIp->ip_dst : newIpAddr,
        pFltPkt->pIp->ip_src,
        0x1400, // always has to be 20-th port (net order)
        (USHORT)((addr[4] & 0xff) | ((addr[5] << 8) & 0xff00)),
        !bOut,
        IPPROTO_TCP))
    {

        return FALSE;
    }

    if (!bDoModify) {
        //
        // No need to modify packet content
        //
        return 0;
    }

    //
    // construct new port command
    //

    RtlStringCbPrintfA(
        new_port_str,
        sizeof(new_port_str),
        "PORT %u,%u,%u,%u,%u,%u%c%c",
        (UCHAR)new_addr_ptr[0],
        (UCHAR)new_addr_ptr[1],
        (UCHAR)new_addr_ptr[2],
        (UCHAR)new_addr_ptr[3],
        (UCHAR)addr[4],
        (UCHAR)addr[5],
        0xd,
        0xa
    );

    new_addr_len = strlen(new_port_str);

    diff = (int)new_addr_len - (int)org_addr_len;

    if (pFltPkt->uLen + diff > MAX_ETHER_SIZE) {

        return 0;
    }

    //
    // Construct a copy of the packet
    //
    CopyNdisPacketToFltPacket(pFltPkt);

    new_data = (char*)pFltPkt->pTcp + TCP_HDR_LEN(pFltPkt->pTcp);

    if (org_addr_len < tcp_data_len) {

        //
        // TCP data contains something else in addition to PORT command (strange)
        //
        memcpy(new_data + new_addr_len, data + org_addr_len, tcp_data_len - org_addr_len);
    }

    memcpy(new_data, new_port_str, new_addr_len);

    //
    // Update packet description
    //
    pFltPkt->pIp->ip_len = RtlUshortByteSwap(RtlUshortByteSwap(pFltPkt->pIp->ip_len) + diff);
    pFltPkt->uLen += diff;

    return diff;
}


VOID
ProcessTraced(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN NAT_ENTRY *pNatItem,
    IN ULONG newIpAddr,
    IN OUT FLT_PKT* pFltPkt,
    IN BOOLEAN bOut
)
{
    ULONG uDstPort;
    ULONG uSrcPort;
    BOOLEAN bServer = FALSE;
    PLIST_ENTRY pEntry;
    TRACED_CONNECTION *pItem = NULL;
    ULONG prevState = 0;
    BOOLEAN bFound = FALSE;

    if (NULL == pFltPkt->pTcp)
        return;

    uDstPort = RtlUshortByteSwap(pFltPkt->pTcp->th_dport);
    uSrcPort = RtlUshortByteSwap(pFltPkt->pTcp->th_sport);

    if (21 != uDstPort && 21 != uSrcPort) {
        // We are interested in FTP only
        return;
    }

    NdisAcquireSpinLock(&pNatItem->Lock);

    for (pEntry = pNatItem->TracedList.Flink; pEntry != &pNatItem->TracedList; pEntry = pEntry->Flink) {

        pItem = (TRACED_CONNECTION*)CONTAINING_RECORD(pEntry, TRACED_CONNECTION, ListEntry);

        if (pFltPkt->pIp->ip_src == pItem->srcIpAddrOrg &&
            pFltPkt->pIp->ip_dst == pItem->dstIpAddrOrg &&
            pFltPkt->pTcp->th_sport == pItem->srcPortOrg &&
            pFltPkt->pTcp->th_dport == pItem->dstPortOrg
            )
        {
            bFound = TRUE;
            bServer = FALSE;
            break;

        }
        else if (pFltPkt->pIp->ip_src == pItem->srcIpAddrNew &&
            pFltPkt->pIp->ip_dst == pItem->dstIpAddrNew &&
            pFltPkt->pTcp->th_sport == pItem->srcPortNew &&
            pFltPkt->pTcp->th_dport == pItem->dstPortNew
            )
        {
            bFound = TRUE;
            bServer = TRUE;
            break;
        }

    }// for(...

    if (bFound) {

        KeQuerySystemTime(&pItem->UpdateTime);

        prevState = pItem->state;
        pItem->state = natuSessionGetState(prevState, pFltPkt->pTcp->th_flags, bServer);

        if (bServer) {

            if (pItem->cln_seq_diff)
                pFltPkt->pTcp->th_ack = RtlUlongByteSwap(RtlUlongByteSwap(pFltPkt->pTcp->th_ack) - pItem->cln_seq_diff);

        }
        else {

            int diff;
            BOOLEAN bDoModify = pNatItem->prvIpAddr == pFltPkt->pIp->ip_src;

            diff = natFixFtpPortContentAndCreateFwSession(
                pAdapter,
                pFltPkt,
                newIpAddr,
                bDoModify,
                bOut
            );

            if (bDoModify && pItem->cln_seq != pFltPkt->pTcp->th_seq) {

                if (pItem->cln_seq_diff)
                    pFltPkt->pTcp->th_seq = RtlUlongByteSwap(RtlUlongByteSwap(pFltPkt->pTcp->th_seq) + pItem->cln_seq_diff);

                pItem->cln_seq_diff += diff;
            }
        }
    }

    if (bFound) {

        if (g_LogPktNAT && prevState != pItem->state)
            natvLogSession("NAT", pItem, prevState, "changed");

        NdisReleaseSpinLock(&pNatItem->Lock);
        return;
    }

    //
    // Try to create session
    // 
    if (TCP_SYN_FLAG != pFltPkt->pTcp->th_flags) {
        NdisReleaseSpinLock(&pNatItem->Lock);
        return;
    }

    //
    // FTP only
    //  
    if (21 != uDstPort) {
        NdisReleaseSpinLock(&pNatItem->Lock);
        return;
    }

    //
    // Create a new traced connection
    //
    pItem = ExAllocatePoolWithTag(0, sizeof(TRACED_CONNECTION), 'rT1N');
    if (NULL == pItem) {
        NdisReleaseSpinLock(&pNatItem->Lock);
        return;
    }
    RtlZeroMemory(pItem, sizeof(TRACED_CONNECTION));

    pItem->state = SESSION_STATE_SYN_RCV;
    pItem->srcPortOrg = pFltPkt->pTcp->th_sport;
    pItem->dstPortOrg = pFltPkt->pTcp->th_dport;
    pItem->srcIpAddrOrg = pFltPkt->pIp->ip_src;
    pItem->dstIpAddrOrg = pFltPkt->pIp->ip_dst;

    if (pItem->srcIpAddrOrg == pNatItem->prvIpAddr) {

        pItem->srcPortNew = pFltPkt->pTcp->th_dport;
        pItem->dstPortNew = pFltPkt->pTcp->th_sport;
        pItem->srcIpAddrNew = pFltPkt->pIp->ip_dst;
        pItem->dstIpAddrNew = pNatItem->pubIpAddr;

    }
    else if (pItem->dstIpAddrOrg == pNatItem->pubIpAddr) {

        pItem->srcPortNew = pFltPkt->pTcp->th_dport;
        pItem->dstPortNew = pFltPkt->pTcp->th_sport;
        pItem->srcIpAddrNew = pNatItem->prvIpAddr;
        pItem->dstIpAddrNew = pFltPkt->pIp->ip_src;
    }
    else {

        ASSERT(FALSE);
    }

    if (g_LogPktNAT)
        natvLogSession("NAT", pItem, prevState, "created");

    pItem->pNatItem = pNatItem;

    pItem->cln_seq_diff = 0;
    pItem->cln_seq = pFltPkt->pTcp->th_seq;
    KeQuerySystemTime(&pItem->UpdateTime);

    InsertHeadList(&pNatItem->TracedList, &pItem->ListEntry);
    NdisReleaseSpinLock(&pNatItem->Lock);

    NdisAcquireSpinLock(&g_TracedSpinLock);
    InsertHeadList(&g_TracedList, &pItem->GlobalEntry);
    NdisReleaseSpinLock(&g_TracedSpinLock);

}

VOID
RecalcChecksums(
    IN OUT FLT_PKT* pFltPkt
)
{
    IP_HDR	*pIp;
    ULONG ip_len;
    ULONG hlen;
    ULONG csum;
    struct pseudoheader
    {
        ULONG	sip, dip;
        UCHAR	zero;
        UCHAR	protocol;
        USHORT	tcplen;
    };
    struct pseudoheader ph;

    pIp = (IP_HDR*)pFltPkt->pIp;

    ip_len = RtlUshortByteSwap(pIp->ip_len);
    hlen = pIp->ip_hlen << 2;

    csum = 0;

    if (pFltPkt->pTcp) {

        pFltPkt->pTcp->th_sum = 0;

        ph.sip = pIp->ip_src;
        ph.dip = pIp->ip_dst;
        ph.zero = 0;
        ph.protocol = pIp->ip_proto;
        ph.tcplen = RtlUshortByteSwap((USHORT)(ip_len - hlen));

        XSUM(csum, &ph, sizeof(ph), 0);

        if (pFltPkt->pData) {
            //
            // TCP data and TCP header are placed in different MDLs
            //
            ULONG TcpHdrLen = TCP_HDR_LEN(pFltPkt->pTcp);

            XSUM(csum, pFltPkt->pTcp, TcpHdrLen, 0);
            XSUM(csum, pFltPkt->pData, ip_len - hlen - TcpHdrLen, 0);

        }
        else {
            //
            // TCP data and TCP header are placed continuously in the memory
            //
            XSUM(csum, pFltPkt->pTcp, ip_len - hlen, 0);
        }

        pFltPkt->pTcp->th_sum = (USHORT)~csum;

    }
    else if (pFltPkt->pUdp) {

        pFltPkt->pUdp->uh_chk = 0;

        ph.sip = pIp->ip_src;
        ph.dip = pIp->ip_dst;
        ph.zero = 0;
        ph.protocol = pIp->ip_proto;
        ph.tcplen = RtlUshortByteSwap((USHORT)(ip_len - hlen));

        XSUM(csum, &ph, 12, 0);

        if (pFltPkt->pData) {
            //
            // data and UDP header are placed in different MDLs
            //
            XSUM(csum, pFltPkt->pUdp, sizeof(UDP_HDR), 0);
            XSUM(csum, pFltPkt->pData, ip_len - hlen - sizeof(UDP_HDR), 0);

        }
        else {

            //
            // data and UDP header are placed continuously in the memory
            //

            XSUM(csum, pFltPkt->pUdp, ip_len - hlen, 0);
        }

        pFltPkt->pUdp->uh_chk = (USHORT)~csum;
    }

    pIp->ip_csum = 0;
    csum = 0;

    XSUM(csum, pIp, hlen, 0);

    pIp->ip_csum = (USHORT)~csum;
}

VOID
TracedTimerFunction(
    IN struct _KDPC *Dpc,
    IN PVOID DeferredContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
)
{
    PLIST_ENTRY			pListEntry = NULL;
    TRACED_CONNECTION	*pItem = NULL;
    LIST_ENTRY			ExpiredSessionsList;
    LARGE_INTEGER		CurrentTime;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    InitializeListHead(&ExpiredSessionsList);

    KeQuerySystemTime(&CurrentTime);

    NdisAcquireSpinLock(&g_TracedSpinLock);

    for (pListEntry = g_TracedList.Flink; pListEntry != &g_TracedList;)
    {
        LONGLONG CurTimeOut = INIT_SESSION_TIMEOUT_SEC;

        pItem = CONTAINING_RECORD(pListEntry, TRACED_CONNECTION, GlobalEntry);

        switch (pItem->state) {
        case SESSION_STATE_ESTABLISHED:
            CurTimeOut = IDLE_SESSION_TIMEOUT_SEC;
            break;
        case SESSION_STATE_UNKNOWN:
        case SESSION_STATE_SYN_RCV:
        case SESSION_STATE_SYN_ACK_RCV:
        case SESSION_STATE_CLOSED:
            CurTimeOut = INIT_SESSION_TIMEOUT_SEC;
            break;
        case SESSION_STATE_FIN_CLN_RCV:
        case SESSION_STATE_FIN_SRV_RCV:
            CurTimeOut = HALF_CLOSED_SESSION_TIMEOUT_SEC;
            break;
        }

        if (CurrentTime.QuadPart - pItem->UpdateTime.QuadPart < SECONDS(CurTimeOut)) {

            pListEntry = pListEntry->Flink;
            continue;
        }

        //
        // this traced session is timed out
        //
        pListEntry = pListEntry->Flink;

        //
        // Remove it from global list
        //
        RemoveEntryList(&pItem->GlobalEntry);

        ASSERT(pItem->pNatItem);

        //
        // Remove traced item from NAT entry list
        //
        NdisAcquireSpinLock(&pItem->pNatItem->Lock);
        RemoveEntryList(&pItem->ListEntry);
        NdisReleaseSpinLock(&pItem->pNatItem->Lock);

        if (g_LogPktNAT)
            natvLogSession("NAT", pItem, pItem->state, "deleted");

        //
        // Free the memory
        // 
        ExFreePool(pItem);
    }

    NdisReleaseSpinLock(&g_TracedSpinLock);

}

ULONG
natuSessionGetState(
    ULONG state,
    ULONG flags,
    BOOLEAN bServer
)
{
    ULONG newState = SESSION_STATE_UNKNOWN;

    flags &= (TCP_ACK_FLAG | TCP_FIN_FLAG | TCP_SYN_FLAG | TCP_RST_FLAG);

    switch (state) {
    case SESSION_STATE_UNKNOWN:

        if (TCP_SYN_FLAG == flags)
            newState = SESSION_STATE_SYN_RCV;
        break;

    case SESSION_STATE_SYN_RCV:

        if ((flags & TCP_RST_FLAG) && bServer) {
            newState = SESSION_STATE_CLOSED;
            break;
        }

        if ((flags == TCP_SYN_FLAG) && !bServer) {
            // duplicate SYN
            newState = SESSION_STATE_SYN_RCV;
            break;
        }

        if ((flags == (TCP_SYN_FLAG | TCP_ACK_FLAG)) && bServer)
            newState = SESSION_STATE_SYN_ACK_RCV;
        else {
            newState = SESSION_STATE_CLOSED;
        }
        break;

    case SESSION_STATE_SYN_ACK_RCV:

        if ((flags & TCP_ACK_FLAG) && (flags & TCP_RST_FLAG) && !bServer) {
            newState = SESSION_STATE_CLOSED;
            break;
        }

        if ((flags == TCP_ACK_FLAG) && !bServer) {

            newState = SESSION_STATE_ESTABLISHED;
            break;
        }

        if ((flags & TCP_ACK_FLAG) && (flags & TCP_SYN_FLAG) && bServer) {
            newState = SESSION_STATE_SYN_ACK_RCV;
            break;
        }

        if ((flags == TCP_SYN_FLAG) && !bServer) {
            newState = SESSION_STATE_SYN_ACK_RCV;
            break;
        }

        newState = SESSION_STATE_CLOSED;
        break;

    case SESSION_STATE_ESTABLISHED:

        if (flags & TCP_SYN_FLAG) {

            if ((flags & TCP_ACK_FLAG) && bServer) {
                newState = SESSION_STATE_ESTABLISHED;
                break;
            }

            if (!(flags & TCP_ACK_FLAG) && !bServer) {

                newState = SESSION_STATE_ESTABLISHED;
                break;
            }

            newState = SESSION_STATE_CLOSED;
            break;
        }

        if (flags & TCP_RST_FLAG) {

            newState = SESSION_STATE_CLOSED;
            break;
        }

        if (flags & TCP_FIN_FLAG) {

            if (!bServer) {
                newState = SESSION_STATE_FIN_CLN_RCV;
                break;
            }
            else {
                newState = SESSION_STATE_FIN_SRV_RCV;
                break;
            }
        }

        newState = SESSION_STATE_ESTABLISHED;
        break;

    case SESSION_STATE_FIN_SRV_RCV:

        if (flags & TCP_SYN_FLAG) {

            newState = SESSION_STATE_CLOSED;
            break;
        }

        newState = SESSION_STATE_FIN_SRV_RCV;

        if (flags & TCP_RST_FLAG) {

            newState = SESSION_STATE_CLOSED;
        }
        else {

            if ((flags & TCP_FIN_FLAG) && !bServer)
                newState = SESSION_STATE_CLOSED;
        }
        break;

    case SESSION_STATE_FIN_CLN_RCV:

        if (flags & TCP_SYN_FLAG) {

            newState = SESSION_STATE_CLOSED;
            break;
        }

        newState = SESSION_STATE_FIN_CLN_RCV;

        if (flags & TCP_RST_FLAG) {

            newState = SESSION_STATE_CLOSED;

        }
        else {

            if ((flags & TCP_FIN_FLAG) && bServer)
                newState = SESSION_STATE_CLOSED;
        }
        break;

    case SESSION_STATE_CLOSED:
    default:

        newState = SESSION_STATE_CLOSED;
        break;
    }

    if ((newState == SESSION_STATE_CLOSED) && (flags & TCP_SYN_FLAG))
    {
        if ((flags == (TCP_SYN_FLAG | TCP_ACK_FLAG)) && bServer)
            newState = SESSION_STATE_SYN_ACK_RCV;
    }

    return newState;
}
