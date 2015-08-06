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

#ifndef ABSOLUTE
#define ABSOLUTE(wait) (wait)
#endif

#ifndef RELATIVE
#define RELATIVE(wait) (-(wait))
#endif

#ifndef NANOSECONDS
#define NANOSECONDS(nanos) \
	(((signed __int64)(nanos)) / 100L)
#endif

#ifndef MICROSECONDS
#define MICROSECONDS(micros) \
	(((signed __int64)(micros)) * NANOSECONDS(1000L))
#endif

#ifndef MILLISECONDS
#define MILLISECONDS(milli) \
	(((signed __int64)(milli)) * MICROSECONDS(1000L))
#endif

#ifndef SECONDS
#define SECONDS(seconds) \
	(((signed __int64)(seconds)) * MILLISECONDS(1000L))
#endif


#define MAX_RCV_PKT_ARR_SZ 50

#define NAT_HASH_TBL_SZ 128
#define NAT_HASH_TBL_MASK (NAT_HASH_TBL_SZ-1)
#define NAT_HASH_VALUE(ipaddr) (ULONG)(((*((unsigned char*)&(ipaddr)))^(*(((unsigned char*)&(ipaddr))+3)))& NAT_HASH_TBL_MASK)

#define FLT_FW_SESSION_HASH_TBL_SZ 128
#define FLT_FW_SESSION_HASH_TBL_MASK (FLT_FW_SESSION_HASH_TBL_SZ-1)
#define FLT_FW_SESSION_HASH_VALUE(a1,p1,a2,p2) (((a1) ^ (a2) ^ (p1) ^ (p2))&FLT_FW_SESSION_HASH_TBL_MASK)

typedef struct _NAT_ENTRY{

	LIST_ENTRY	InEntry;
	LIST_ENTRY	OutEntry;

	ULONG		prvIpAddr;
	ULONG		pubIpAddr;

	NDIS_SPIN_LOCK Lock;
	LIST_ENTRY	TracedList;

}NAT_ENTRY;

typedef struct _TRACED_CONNECTION{

	LIST_ENTRY	ListEntry;
	LIST_ENTRY	GlobalEntry;

	union{
		ULONG		srcIpAddrOrg;
		ULONG		srcIpAddr;
	};
	union{
		ULONG		dstIpAddrOrg;
		ULONG		dstIpAddr;
	};
	union{
		USHORT		srcPortOrg;
		USHORT		srcPort;
	};
	union{
		USHORT		dstPortOrg;
		USHORT		dstPort;
	};

	ULONG		srcIpAddrNew;
	ULONG		dstIpAddrNew;
	USHORT		srcPortNew;
	USHORT		dstPortNew;

	ULONG		protocol;
	ULONG		out;

	int			cln_seq_diff;
	ULONG		cln_seq;

	LARGE_INTEGER UpdateTime;
	ULONG		state;

	union{
		PVOID		pAdapter;
		NAT_ENTRY	*pNatItem;
	};

}TRACED_CONNECTION, FLT_FW_SESSION;

typedef enum _SESSION_STATE{

	SESSION_STATE_UNKNOWN = 0,
	SESSION_STATE_CLOSED,
	SESSION_STATE_SYN_RCV,
	SESSION_STATE_SYN_ACK_RCV,
	SESSION_STATE_ESTABLISHED,
	SESSION_STATE_FIN_CLN_RCV,
	SESSION_STATE_FIN_SRV_RCV,

}SESSION_STATE;

#define IDLE_SESSION_TIMEOUT_SEC 3600*24
#define INIT_SESSION_TIMEOUT_SEC 10
#define HALF_CLOSED_SESSION_TIMEOUT_SEC 10*60


typedef struct _NAT_HASH_TABLE{

	NDIS_SPIN_LOCK Locks[NAT_HASH_TBL_SZ];
	LIST_ENTRY	   List[NAT_HASH_TBL_SZ];

}NAT_HASH_TABLE;

typedef struct _FLT_RULE
{
	LIST_ENTRY ListEntry;
	ULONG prvAddr;
	ULONG prvMask;
	ULONG pubAddr;
	ULONG pubMask;
	ULONG port;
	ULONG out;
}FLT_RULE;


typedef struct _FILTER_COMMON_CONTROL_BLOCK{

	LIST_ENTRY					ListEntry;

	LIST_ENTRY					TcpRuleList;
	NDIS_SPIN_LOCK			TcpRuleLock;

	LIST_ENTRY					UdpRuleList;
	NDIS_SPIN_LOCK			UdpRuleLock;

	LIST_ENTRY					IcmpRuleList;
	NDIS_SPIN_LOCK			IcmpRuleLock;

	NDIS_SPIN_LOCK			FwSessionLocks[FLT_FW_SESSION_HASH_TBL_SZ];
	LIST_ENTRY					FwSessionList[FLT_FW_SESSION_HASH_TBL_SZ];

	NAT_HASH_TABLE			NatIncoming;
	NAT_HASH_TABLE			NatOutgoing;

	union{

		UCHAR			Arr[6];
		ULONGLONG		Val;
	}MacAddr;

	ULONG								bStarted;
	ULONG								bFiltered;

}FILTER_COMMON_CONTROL_BLOCK, *PFILTER_COMMON_CONTROL_BLOCK;

#define NAT_TAG 'dA1N'


extern LIST_ENTRY					g_AdapterListHead;
extern NDIS_SPIN_LOCK			g_AdapterListLock;
