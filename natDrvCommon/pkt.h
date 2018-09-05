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

#pragma once

typedef struct _FLT_PKT {

    ULONG	uLen;
    ULONG	Incoming;
    ETH_HDR *pEth;
    ETH_ARP *pArp;
    IP_HDR	*pIp;
    TCP_HDR *pTcp;
    UDP_HDR *pUdp;
    ICMP_HDR*pIcmp;
    PVOID	pData;
    PVOID	pOrgPkt;
    PVOID	pBuf;
    struct _FLT_PKT* pNext;

}FLT_PKT;

#define NAT_LOG_REG_VALUE_NAT			L"PktLogNAT"
#define NAT_LOG_REG_VALUE_PASS			L"PktLogPASS"
#define NAT_LOG_REG_VALUE_DROP			L"PktLogDROP"

#define NAT_FLT_SIGNATURE               'pNwG'

extern ULONG g_LogPktDrop;
extern ULONG g_LogPktPass;
extern ULONG g_LogPktNAT;

#define PRINT_IP(m,ip_addr) RtlStringCbPrintfA( \
								m,sizeof(m), \
								"%u.%u.%u.%u", \
								*(unsigned char*)ip_addr, \
								*((unsigned char*)ip_addr+1), \
								*((unsigned char*)ip_addr+2), \
								*((unsigned char*)ip_addr+3) \
								)

BOOLEAN
natbParsePacket(
    IN PVOID	Pkt,
    IN OUT FLT_PKT* pFltPkt
);

BOOLEAN
natCopyPacketData(
    IN PVOID	Pkt,
    IN OUT PUCHAR lpBuffer,
    IN ULONG		nNumberOfBytesToRead,
    IN ULONG		nOffset,
    IN PULONG lpNumberOfBytesRead,
    IN BOOLEAN			bWirelessWan
);

VOID InitPacketLookaside();
VOID ReleasePacketLookaside();
VOID natInitTraced();
VOID natReleaseTracedAll();
void natInitControlBlock(IN PFILTER_COMMON_CONTROL_BLOCK pAdapter);
VOID natFreeAllItems(IN PFILTER_COMMON_CONTROL_BLOCK pAdapter);
VOID
natFreeAllFwSessionsAndRules(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter
);

void natvDumpAllRules(IN PFILTER_COMMON_CONTROL_BLOCK pAdapter);

VOID natInitFwSession();
VOID natDeinitFwSession();
VOID
natReadRegValues(
    IN PUNICODE_STRING	RegistryPath
);


BOOLEAN
natbFwSessionCreate(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN ULONG srcIpAddr,
    IN ULONG dstIpAddr,
    IN USHORT srcPort,
    IN USHORT dstPort,
    IN ULONG bOutgoing,
    IN UCHAR uProto
);

FLT_PKT*
AllocateFltPacket();

FLT_PKT*
CreateFltPacketWithBuffer();

VOID FreeFltPkt(
    IN FLT_PKT* pFltPkt
);

BOOLEAN
TranslatePktIncoming(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN OUT FLT_PKT* pFltPkt
);

BOOLEAN
TranslatePktOutgoing(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN OUT FLT_PKT* pFltPkt
);

BOOLEAN
FilterPkt(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN OUT FLT_PKT* pFltPkt,
    IN BOOLEAN bOutgoing
);

BOOLEAN
CopyNdisPacketToFltPacket(
    IN FLT_PKT* pFltPkt
);


VOID
natInsertEntry(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapter,
    IN NAT_ENTRY *pItem
);

VOID PrintFtlPkt(
    IN char *strPrefix,
    IN FLT_PKT* pFltPkt,
    IN ULONG uNewIp,
    IN BOOLEAN bOut
);

NDIS_STATUS
natmSendFltPacket(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdapt,
    IN FLT_PKT* pFltPkt
);

ULONG
natuSessionGetState(
    ULONG state,
    ULONG flags,
    BOOLEAN bServer
);

void
natvLogSession(
    IN const char * prefixStr,
    IN TRACED_CONNECTION* pItem,
    IN ULONG prevState,
    IN const char * sufixStr
);
