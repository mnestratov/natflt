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

#ifndef _NETGW_H
#define _NETGW_H

#define FILTER_REQUEST_ID			'RtlF'

#define FILTER_MAJOR_NDIS_VERSION   6
#define FILTER_MINOR_NDIS_VERSION   0


#define MAX_PACKET_POOL_SIZE    0x0000FFFF
#define MIN_PACKET_POOL_SIZE    0x000000FF
#define PROTOCOL_RESERVED       4

 //
 // Flags for filter's state
 //
#define FILTER_PAUSING          0x00000001
#define FILTER_PAUSED           0x00000002
#define FILTER_DETACHING        0x00000004
#define FILTER_ATTACHED         0x00000008
#define FILTER_RUNNING          0x00000010


#define FILTER_ALLOC_TAG            'AtlF'
#define FILTER_TAG                  'DtlF'

extern NDIS_HANDLE				FilterDriverHandle;
extern NDIS_HANDLE				FilterDriverObject;
extern NDIS_HANDLE				NdisFilterDeviceHandle;
extern PDEVICE_OBJECT			DeviceObject;
extern NDIS_HANDLE g_PoolNetBufferList;

#define NET_BUFFER_LIST_LINK_TO_ENTRY(_pNBL)    ((PQUEUE_ENTRY)(NET_BUFFER_LIST_NEXT_NBL(_pNBL)))
#define ENTRY_TO_NET_BUFFER_LIST(_pEnt)         (CONTAINING_RECORD((_pEnt), NET_BUFFER_LIST, Next))

typedef struct _INTERNAL_OID_REQUEST
{
    NDIS_STATUS			Status;
    PNDIS_OID_REQUEST	pReq;
    PNDIS_OID_REQUEST	pOrigReq;
    NDIS_OID_REQUEST    NdisReq;
    BOOLEAN				bLocal;

}INTERNAL_OID_REQUEST, *PINTERNAL_OID_REQUEST;

typedef struct _NETGW_ADAPT {

    FILTER_COMMON_CONTROL_BLOCK ctrl;
    NDIS_SPIN_LOCK Lock;
    LONG		State;
    LONG		TRxPending;

    NDIS_HANDLE	FilterHandle;
    NDIS_STRING FilterModuleName;
    NDIS_STRING MiniportFriendlyName;
    NDIS_STRING MiniportName;
    NET_IFINDEX MiniportIfIndex;
    ULONG		Flags;
    UCHAR		m_RemoteAddress[6];
    UCHAR		m_LocalAddress[6];

    LIST_ENTRY	m_WanLinksList;
    NDIS_SPIN_LOCK	m_WanLinksLock;

    NDIS_MEDIUM	m_Medium;
    ULONG		m_usMTU;
    NDIS_OFFLOAD_PARAMETERS m_OffloadParam;
    INTERNAL_OID_REQUEST m_IntReq;

}NETGW_ADAPT, *PNETGW_ADAPT;

typedef void PROTOCOL_ENTRY, *PPROTOCOL_ENTRY;

typedef struct _FILTER_DEVICE_EXTENSION
{
    ULONG            Signature;
    NDIS_HANDLE      Handle;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;

typedef struct _FLT_PKT_CTX {
    ULONG Signature;
    ULONG Size;
    PVOID pFltPkt;
}FLT_PKT_CTX;

//
// The context inside a cloned request
//
typedef struct _NDIS_OID_REQUEST *FILTER_REQUEST_CONTEXT, **PFILTER_REQUEST_CONTEXT;

#define ntohs(x) RtlUshortByteSwap(x)
#define htons(x) RtlUshortByteSwap(x)
#define ntohl(x) RtlUlongByteSwap(x)
#define htonl(x) RtlUlongByteSwap(x)

//
// function prototypes
//
NDIS_STATUS
DriverEntry(
    IN  PDRIVER_OBJECT      DriverObject,
    IN  PUNICODE_STRING     RegistryPath
);

NDIS_STATUS
FilterRegisterOptions(
    IN NDIS_HANDLE      NdisFilterDriverHandle,
    IN NDIS_HANDLE      FilterDriverContext
);

NDIS_STATUS
FilterAttach(
    IN  NDIS_HANDLE                     NdisFilterHandle,
    IN  NDIS_HANDLE                     FilterDriverContext,
    IN  PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters
);

VOID
FilterDetach(
    IN  NDIS_HANDLE     FilterInstaceContext
);

DRIVER_UNLOAD FilterUnload;

VOID
FilterUnload(
    IN  PDRIVER_OBJECT  DriverObject
);

NDIS_STATUS
FilterRestart(
    IN  NDIS_HANDLE     FilterModuleContext,
    IN  PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
);

NDIS_STATUS
FilterPause(
    IN  NDIS_HANDLE     FilterModuleContext,
    IN  PNDIS_FILTER_PAUSE_PARAMETERS   PauseParameters
);


NDIS_STATUS
FilterOidRequest(
    IN  NDIS_HANDLE        FilterModuleContext,
    IN  PNDIS_OID_REQUEST  Request
);

NDIS_STATUS
FilterDoInternalRequest(
    IN PNETGW_ADAPT FilterModuleContext,
    IN NDIS_REQUEST_TYPE RequestType,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    IN ULONG OutputBufferLength
);

VOID
FilterCancelOidRequest(
    IN  NDIS_HANDLE             FilterModuleContext,
    IN  PVOID                   RequestId
);

VOID
FilterStatus(
    IN  NDIS_HANDLE                 FilterModuleContext,
    IN  PNDIS_STATUS_INDICATION     StatusIndication
);

VOID
FilterDevicePnPEventNotify(
    IN  NDIS_HANDLE            FilterModuleContext,
    IN  PNET_DEVICE_PNP_EVENT  NetDevicePnPEvent
);

NDIS_STATUS
FilterNetPnPEvent(
    IN NDIS_HANDLE              FilterModuleContext,
    IN PNET_PNP_EVENT_NOTIFICATION     NetPnPEventNotification
);

VOID
FilterOidRequestComplete(
    IN  NDIS_HANDLE        FilterModuleContext,
    IN  PNDIS_OID_REQUEST  Request,
    IN  NDIS_STATUS        Status
);

VOID
FilterSendNetBufferLists(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               SendFlags
);

VOID
FilterReturnNetBufferLists(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               ReturnFlags
);

VOID
FilterSendNetBufferListsComplete(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               SendCompleteFlags
);


VOID
FilterReceiveNetBufferLists(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               NumberOfNetBufferLists,
    IN  ULONG               ReceiveFlags
);

VOID
FilterCancelSendNetBufferLists(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PVOID               CancelId
);

NDIS_STATUS
FilterSetModuleOptions(
    IN  NDIS_HANDLE             FilterModuleContext
);


NDIS_STATUS
FilterRegisterDevice(
    VOID
);

VOID
FilterDeregisterDevice(
    VOID
);

DRIVER_DISPATCH FilterDispatch;

NTSTATUS
FilterDispatch(
    IN PDEVICE_OBJECT       DeviceObjet,
    IN PIRP                 Irp
);

DRIVER_DISPATCH FilterDeviceIoControl;

NTSTATUS
FilterDeviceIoControl(
    IN PDEVICE_OBJECT        DeviceObject,
    IN PIRP                  Irp
);

PNETGW_ADAPT
filterFindFilterModule(
    IN PUCHAR                   FilterModuleName,
    IN ULONG                    BufferLength
);

PVOID natGetFltPktFromContext(
    PNET_BUFFER_LIST pNBL
);

USHORT natGetFltPktContextSize();


#endif  //_NDISRD_H


