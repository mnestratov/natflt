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

static KTIMER g_FwSessionTimer;
static KDPC g_FwSessionDpc;
static LIST_ENTRY g_FwSessionList;
static NDIS_SPIN_LOCK g_FwSessionLock;

static BOOLEAN
	natbFwIsAllowedByRule(
		IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
		IN FLT_PKT* pFltPkt,
		IN ULONG bOutgoing
	   )
{
	FLT_RULE *pRule;
	PLIST_ENTRY pRuleHead;
	PLIST_ENTRY pRuleEntry;
	NDIS_SPIN_LOCK	*pRuleLock;
	ULONG uPort;
	ULONG uPrvIpAddr, uPubIpAddr;
	BOOLEAN bAllowed = FALSE;

	if(pFltPkt->pTcp){
		// ignore TCP_ECE_FLAG
		if(TCP_SYN_FLAG != (~(TCP_ECE_FLAG | TCP_CWR_FLAG) & pFltPkt->pTcp->th_flags)){
			return FALSE;
		}

		pRuleHead = &pAdapter->TcpRuleList;
		pRuleLock = &pAdapter->TcpRuleLock;
		uPort = pFltPkt->pTcp->th_dport;

	} else if (pFltPkt->pUdp) {
		
		pRuleHead = &pAdapter->UdpRuleList;
		pRuleLock = &pAdapter->UdpRuleLock;
		uPort = pFltPkt->pUdp->uh_dport;
	
	} else if (pFltPkt->pIcmp) {
	
		pRuleHead = &pAdapter->IcmpRuleList;
		pRuleLock = &pAdapter->IcmpRuleLock;
		uPort = 0;

	}else{
		return FALSE;
	}

	if(bOutgoing){
		uPrvIpAddr = pFltPkt->pIp->ip_src;
		uPubIpAddr = pFltPkt->pIp->ip_dst;
	}else{
		uPrvIpAddr = pFltPkt->pIp->ip_dst;
		uPubIpAddr = pFltPkt->pIp->ip_src;
	}

	NdisAcquireSpinLock(pRuleLock);

	for(pRuleEntry = pRuleHead->Flink; pRuleEntry != pRuleHead; pRuleEntry = pRuleEntry->Flink ){

		pRule = CONTAINING_RECORD(pRuleEntry, FLT_RULE, ListEntry);
		if(pRule->out == bOutgoing &&
			(0 == pRule->port || (pRule->port == uPort)) &&
			(pRule->prvAddr & pRule->prvMask) == (uPrvIpAddr & pRule->prvMask) &&
			(pRule->pubAddr & pRule->pubMask) == (uPubIpAddr & pRule->pubMask)
			)
		{

			bAllowed = TRUE;
			break;
		}
	}

	NdisReleaseSpinLock(pRuleLock);

	return bAllowed;

}

static BOOLEAN
	natbFwSessionExists(
		IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
		IN FLT_PKT* pFltPkt,
		IN ULONG bOutgoing
	)
{
	BOOLEAN bFound = FALSE;
	BOOLEAN bServer = FALSE;
	NDIS_SPIN_LOCK	*pSessionLock;
	PLIST_ENTRY		pSessionList;
	PLIST_ENTRY		pEntry;
	ULONG uHashindex;
	FLT_FW_SESSION *pFwSess = NULL;
	ULONG		srcIpAddr;
	ULONG		dstIpAddr;
	USHORT		srcPort;
	USHORT		dstPort;
	ULONG		flags = 0;

	if(pFltPkt->pTcp){

		srcPort = pFltPkt->pTcp->th_sport;
		dstPort = pFltPkt->pTcp->th_dport;
		flags = pFltPkt->pTcp->th_flags;

	} else if (pFltPkt->pUdp) {
		
		srcPort = pFltPkt->pUdp->uh_sport;
		dstPort = pFltPkt->pUdp->uh_dport;
	
	} else if (pFltPkt->pIcmp) {
	
		srcPort = pFltPkt->pIcmp->icmp_hun.idseq.id;
		dstPort = pFltPkt->pIcmp->icmp_hun.idseq.id;

	}else{

		return FALSE;
	}

	srcIpAddr = pFltPkt->pIp->ip_src;
	dstIpAddr = pFltPkt->pIp->ip_dst;

	uHashindex = FLT_FW_SESSION_HASH_VALUE(
		srcIpAddr, 
		srcPort,
		dstIpAddr,
		dstPort);

	pSessionLock = pAdapter->FwSessionLocks + uHashindex;
	pSessionList = pAdapter->FwSessionList + uHashindex;

	NdisAcquireSpinLock(pSessionLock);

	for(pEntry = pSessionList->Flink; pEntry != pSessionList; pEntry = pEntry->Flink){

		pFwSess = CONTAINING_RECORD(pEntry, FLT_FW_SESSION, ListEntry);

		if(pFwSess->protocol != pFltPkt->pIp->ip_proto)
			continue;

		if(pFwSess->out == bOutgoing){

			if(
				srcIpAddr == pFwSess->srcIpAddr && 
				srcPort  == pFwSess->srcPort && 
				dstIpAddr == pFwSess->dstIpAddr && 
				dstPort == pFwSess->dstPort
				)
			{
				bFound = TRUE;
				bServer = FALSE;
				break;
			}
		}else{

			if(
				srcIpAddr == pFwSess->dstIpAddr && 
				srcPort  == pFwSess->dstPort && 
				dstIpAddr == pFwSess->srcIpAddr && 
				dstPort == pFwSess->srcPort
				)
			{
				bFound = TRUE;
				bServer = TRUE;
				break;
			}
		}
	}

	if(bFound){

		ULONG prevState = pFwSess->state;
		pFwSess->state = natuSessionGetState(pFwSess->state, flags, bServer);
		if(pFwSess->state != prevState)
			natvLogSession("FIREWALL", pFwSess, prevState, "changed");

		KeQuerySystemTime (&pFwSess->UpdateTime);
	}

	NdisReleaseSpinLock(pSessionLock);

	return bFound;
}

BOOLEAN 
	natbFwSessionCreate(
		IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
		IN ULONG srcIpAddr,
		IN ULONG dstIpAddr,
		IN USHORT srcPort,
		IN USHORT dstPort,
		IN ULONG bOutgoing,
		IN UCHAR uProto
	)
{
	NDIS_SPIN_LOCK	*pSessionLock;
	PLIST_ENTRY		pSessionList;
	ULONG uHashindex;
	FLT_FW_SESSION *pFwSess;

	uHashindex = FLT_FW_SESSION_HASH_VALUE(
		srcIpAddr, 
		srcPort,
		dstIpAddr,
		dstPort);

	pSessionLock = pAdapter->FwSessionLocks + uHashindex;
	pSessionList = pAdapter->FwSessionList + uHashindex;

	pFwSess = ExAllocatePoolWithTag(0, sizeof(FLT_FW_SESSION), 'sF1N');
	ASSERT(pFwSess);
	if(NULL == pFwSess){
		return FALSE;
	}

	memset(pFwSess, 0, sizeof(*pFwSess));

	pFwSess->state = SESSION_STATE_SYN_RCV;
	pFwSess->protocol = uProto;
	pFwSess->out = bOutgoing;
	pFwSess->dstIpAddr = dstIpAddr;
	pFwSess->srcIpAddr = srcIpAddr;
	pFwSess->srcPort = srcPort;
	pFwSess->dstPort = dstPort;

	if(g_LogPktPass || g_LogPktDrop)
		natvLogSession("FIREWALL", pFwSess, SESSION_STATE_UNKNOWN, "created");

	KeQuerySystemTime ( &pFwSess->UpdateTime );

	NdisAcquireSpinLock(&g_FwSessionLock);

	NdisAcquireSpinLock(pSessionLock);
	InsertTailList(pSessionList, &pFwSess->ListEntry);
	InsertTailList(&g_FwSessionList, &pFwSess->GlobalEntry);
	pFwSess->pAdapter = pAdapter;
	NdisReleaseSpinLock(pSessionLock);

	NdisReleaseSpinLock(&g_FwSessionLock);

	return TRUE;
}

static VOID 
	natFwSessionTimerFunction(
		 IN struct _KDPC *Dpc,
		 IN PVOID DeferredContext,
		 IN PVOID SystemArgument1,
		 IN PVOID SystemArgument2
		 )
{
	PLIST_ENTRY			pListEntry = NULL;
	FLT_FW_SESSION		*pItem = NULL;
	LIST_ENTRY			ExpiredSessionsList;
	LARGE_INTEGER		CurrentTime = {0};
	PFILTER_COMMON_CONTROL_BLOCK		pAdapter;

	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	InitializeListHead( &ExpiredSessionsList );

	KeQuerySystemTime ( &CurrentTime );

	NdisAcquireSpinLock( &g_FwSessionLock );

	for(pListEntry = g_FwSessionList.Flink; pListEntry != &g_FwSessionList;){
		
		LONGLONG CurTimeOut = INIT_SESSION_TIMEOUT_SEC;
		ULONG uHashindex;
		NDIS_SPIN_LOCK	*pSessionLock;
		PLIST_ENTRY		pSessionList;

		pItem = CONTAINING_RECORD(pListEntry, FLT_FW_SESSION, GlobalEntry);

		switch(pItem->state){
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

		if (CurrentTime.QuadPart - pItem->UpdateTime.QuadPart < SECONDS(CurTimeOut) ){

			pListEntry = pListEntry->Flink;
			continue;
		}	

		if(g_LogPktPass || g_LogPktDrop)
			natvLogSession("FIREWALL", pItem, pItem->state, "deleted");

		//
		// this session is timed out
		//
		pListEntry = pListEntry->Flink;
		
		//
		// Remove it from global list
		//
		RemoveEntryList(&pItem->GlobalEntry);

		//
		// Remove Firewall session item from HASHed Firewall session list
		//

		uHashindex = FLT_FW_SESSION_HASH_VALUE(
			pItem->srcIpAddr, 
			pItem->srcPort,
			pItem->dstIpAddr,
			pItem->dstPort);

		pAdapter = (PFILTER_COMMON_CONTROL_BLOCK)pItem->pAdapter;
		pSessionLock = pAdapter->FwSessionLocks + uHashindex;
		pSessionList = pAdapter->FwSessionList + uHashindex;

		NdisAcquireSpinLock(pSessionLock);
		RemoveEntryList(&pItem->ListEntry);
		NdisReleaseSpinLock(pSessionLock);

		//
		// Free the memory
		// 
		ExFreePool(pItem);
	}

	NdisReleaseSpinLock(  &g_FwSessionLock );
}

VOID natInitFwSession()
{
	LARGE_INTEGER DueTime;

	KeInitializeTimer(&g_FwSessionTimer);
	KeInitializeDpc(&g_FwSessionDpc, natFwSessionTimerFunction, NULL);

	InitializeListHead(&g_FwSessionList);
	NdisAllocateSpinLock(&g_FwSessionLock);

	DueTime.QuadPart = -1;
	KeSetTimerEx(&g_FwSessionTimer, DueTime, INIT_SESSION_TIMEOUT_SEC*1000 ,&g_FwSessionDpc);
}

VOID 
	natDeinitFwSession()
{
	KeCancelTimer(&g_FwSessionTimer);
	KeFlushQueuedDpcs();
}

VOID
	natFreeAllFwSessionsAndRules(
		IN PFILTER_COMMON_CONTROL_BLOCK pAdapter
	)
{
	ULONG i;
	LIST_ENTRY *pFwList;
	NDIS_SPIN_LOCK *pFwListLock;
	LIST_ENTRY *pEntry;
	FLT_FW_SESSION *pFwSession;
	FLT_RULE *pRule;

	//
	// TCP rules
	//
	NdisAcquireSpinLock(&pAdapter->TcpRuleLock);
	while(!IsListEmpty(&pAdapter->TcpRuleList)){

		pEntry = RemoveHeadList(&pAdapter->TcpRuleList);

		pRule  = CONTAINING_RECORD(pEntry, FLT_RULE, ListEntry);

		ExFreePool(pRule);
	}
	NdisReleaseSpinLock(&pAdapter->TcpRuleLock);

	//
	// UDP rules
	//
	NdisAcquireSpinLock(&pAdapter->UdpRuleLock);
	while(!IsListEmpty(&pAdapter->UdpRuleList)){

		pEntry = RemoveHeadList(&pAdapter->UdpRuleList);

		pRule  = CONTAINING_RECORD(pEntry, FLT_RULE, ListEntry);

		ExFreePool(pRule);
	}
	NdisReleaseSpinLock(&pAdapter->UdpRuleLock);

	//
	// ICMP rules
	//
	NdisAcquireSpinLock(&pAdapter->IcmpRuleLock);
	while(!IsListEmpty(&pAdapter->IcmpRuleList)){

		pEntry = RemoveHeadList(&pAdapter->IcmpRuleList);

		pRule  = CONTAINING_RECORD(pEntry, FLT_RULE, ListEntry);

		ExFreePool(pRule);
	}
	NdisReleaseSpinLock(&pAdapter->IcmpRuleLock);

	//
	// Free firewall sessions if any
	//
	for(i = 0;i<FLT_FW_SESSION_HASH_TBL_SZ;i++){

		pFwList = pAdapter->FwSessionList + i;
		pFwListLock = pAdapter->FwSessionLocks + i;

		NdisAcquireSpinLock( &g_FwSessionLock );

		NdisAcquireSpinLock(pFwListLock);

		while(!IsListEmpty(pFwList)){

			pEntry = RemoveHeadList(pFwList);

			pFwSession  = CONTAINING_RECORD(pEntry, FLT_FW_SESSION, ListEntry);

			RemoveEntryList(&pFwSession->GlobalEntry);

			ExFreePool(pFwSession);
		}

		NdisReleaseSpinLock(pFwListLock);
		NdisReleaseSpinLock( &g_FwSessionLock );

		NdisFreeSpinLock(pFwListLock);
	}
}

BOOLEAN
	FilterPkt(
		IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
		IN FLT_PKT* pFltPkt,
		IN BOOLEAN bOutgoing
		)
{
	ULONG srcIpAddr;
	ULONG dstIpAddr;
	USHORT srcPort;
	USHORT dstPort;

	if(pFltPkt->pArp)
		return TRUE;

	if(!pAdapter->bStarted){
		return FALSE;
	}

	if(!pAdapter->bFiltered)
		return TRUE;

	if(NULL == pFltPkt->pIp){
		return FALSE;
	}

	if(natbFwSessionExists(pAdapter, pFltPkt, bOutgoing))
		return TRUE;

	if(!natbFwIsAllowedByRule(pAdapter, pFltPkt, bOutgoing)){
		return FALSE;
	}

	if(pFltPkt->pTcp){

		srcPort = pFltPkt->pTcp->th_sport;
		dstPort = pFltPkt->pTcp->th_dport;

	}else if (pFltPkt->pUdp) {
		
		srcPort = pFltPkt->pUdp->uh_sport;
		dstPort = pFltPkt->pUdp->uh_dport;
	
	}else if (pFltPkt->pIcmp) {

		srcPort = pFltPkt->pIcmp->icmp_hun.idseq.id,
		dstPort = pFltPkt->pIcmp->icmp_hun.idseq.id;

	}else{
		return FALSE;
	}

	srcIpAddr = pFltPkt->pIp->ip_src;
	dstIpAddr = pFltPkt->pIp->ip_dst;

	if(!natbFwSessionCreate(
		pAdapter, 
		srcIpAddr,
		dstIpAddr,
		srcPort,
		dstPort,
		bOutgoing,
		pFltPkt->pIp->ip_proto)){
		return FALSE;
	}

	return TRUE;
}


VOID 
	natReadRegValues(
		IN PUNICODE_STRING	RegistryPath
		)
{
	NTSTATUS			ntStatus;
	OBJECT_ATTRIBUTES	oa;
	HANDLE				hKey;
	UNICODE_STRING		ValueName;
	UCHAR				FlagBuffer[sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof(ULONG)];
	ULONG				resultLength;

	PAGED_CODE();

	InitializeObjectAttributes(
		&oa, RegistryPath, 
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
		NULL, NULL
		);
	
	ntStatus = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);

	if (!NT_SUCCESS(ntStatus)) {
		return;
	}
	
	RtlInitUnicodeString( &ValueName, NAT_LOG_REG_VALUE_NAT );

	ntStatus = 
		ZwQueryValueKey( 
		hKey,
		&ValueName,
		KeyValuePartialInformation,
		FlagBuffer,
		sizeof(FlagBuffer),
		&resultLength 
		);

	if ( NT_SUCCESS( ntStatus ) && 
		((PKEY_VALUE_PARTIAL_INFORMATION)FlagBuffer)->Type == REG_DWORD ) {

			g_LogPktNAT = *((PLONG) &(((PKEY_VALUE_PARTIAL_INFORMATION) FlagBuffer)->Data));
	}


	//////////////////////////////////////////////////////////////////////////

	RtlInitUnicodeString( &ValueName, NAT_LOG_REG_VALUE_PASS );

	ntStatus = 
		ZwQueryValueKey( 
		hKey,
		&ValueName,
		KeyValuePartialInformation,
		FlagBuffer,
		sizeof(FlagBuffer),
		&resultLength 
		);

	if ( NT_SUCCESS( ntStatus ) && 
		((PKEY_VALUE_PARTIAL_INFORMATION)FlagBuffer)->Type == REG_DWORD ) {

		g_LogPktPass = *((PLONG) &(((PKEY_VALUE_PARTIAL_INFORMATION) FlagBuffer)->Data));
	}

	//////////////////////////////////////////////////////////////////////////

	RtlInitUnicodeString( &ValueName, NAT_LOG_REG_VALUE_DROP );

	ntStatus = 
		ZwQueryValueKey( 
		hKey,
		&ValueName,
		KeyValuePartialInformation,
		FlagBuffer,
		sizeof(FlagBuffer),
		&resultLength 
		);

	if ( NT_SUCCESS( ntStatus ) && 
		((PKEY_VALUE_PARTIAL_INFORMATION)FlagBuffer)->Type == REG_DWORD ) {

		g_LogPktDrop = *((PLONG) &(((PKEY_VALUE_PARTIAL_INFORMATION) FlagBuffer)->Data));
	}

	ZwClose(hKey);
}


static void
natvDumpRulesHelper(
	PLIST_ENTRY pRuleHead,
	NDIS_SPIN_LOCK	*pRuleLock
	)
{
	FLT_RULE *pRule;
	PLIST_ENTRY pRuleEntry;
	char pubIpAddrStr[30];
	char prvIpAddrStr[30];
	char pubMaskStr[30];
	char prvMaskStr[30];

	NdisAcquireSpinLock(pRuleLock);

	for(pRuleEntry = pRuleHead->Flink; pRuleEntry != pRuleHead; pRuleEntry = pRuleEntry->Flink ){

		pRule = CONTAINING_RECORD(pRuleEntry, FLT_RULE, ListEntry);

		PRINT_IP(pubIpAddrStr, &pRule->pubAddr);
		PRINT_IP(pubMaskStr, &pRule->pubMask);

		PRINT_IP(prvIpAddrStr, &pRule->prvAddr);
		PRINT_IP(prvMaskStr, &pRule->prvMask);

		DbgPrint("%s RULE: ALLOW PUB=%s/%s PRV=%s/%s DST PORT=%u\n",
			pRule->out ? "OUTGOING" : "INCOMING",
			pubIpAddrStr,pubMaskStr,
			prvIpAddrStr,prvMaskStr,
			RtlUshortByteSwap(pRule->port));
	}

	NdisReleaseSpinLock(pRuleLock);

}

void
natvDumpAllRules(IN PFILTER_COMMON_CONTROL_BLOCK pAdapter)
{
	DbgPrint("---------------------- TCP rules ------------------------\n");
	natvDumpRulesHelper(&pAdapter->TcpRuleList , &pAdapter->TcpRuleLock);
	DbgPrint("---------------------------------------------------------\n");

	DbgPrint("---------------------- UDP rules ------------------------\n");
	natvDumpRulesHelper(&pAdapter->UdpRuleList , &pAdapter->UdpRuleLock);
	DbgPrint("---------------------------------------------------------\n");

	DbgPrint("---------------------- ICMP rules ------------------------\n");
	natvDumpRulesHelper(&pAdapter->IcmpRuleList , &pAdapter->IcmpRuleLock);
	DbgPrint("---------------------------------------------------------\n");
}