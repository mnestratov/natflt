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

#define __FILENUMBER    'wGeN'
#define	  MODULE_TAG1	'wGeN'

#pragma NDIS_INIT_FUNCTION(DriverEntry)

PNET_BUFFER_LIST
filterGetNewNetBufferList(
    FLT_PKT* pFltPkt,
    PNETGW_ADAPT pFilter
);

BOOLEAN
filterSendReceiveNBL(
    IN PNETGW_ADAPT pAdapter,
    IN PNET_BUFFER_LIST  pNBL,
    IN NDIS_PORT_NUMBER PortNumber,
    IN ULONG Flags,
    IN BOOLEAN bSend
);

NDIS_HANDLE FilterDriverHandle;
NDIS_HANDLE FilterDriverObject;
NDIS_HANDLE NdisFilterDeviceHandle = NULL;
PDEVICE_OBJECT DeviceObject = NULL;
NDIS_HANDLE g_PoolNetBufferList = NULL;

NDIS_FILTER_PARTIAL_CHARACTERISTICS DefaultChars = {
    { 0, 0, 0},
    0,
    FilterSendNetBufferLists,
    FilterSendNetBufferListsComplete,
    NULL,
    FilterReceiveNetBufferLists,
    FilterReturnNetBufferLists
};

NDIS_STATUS
DriverEntry(
    IN  PDRIVER_OBJECT      DriverObject,
    IN  PUNICODE_STRING     RegistryPath
)
{
    NDIS_STATUS                			Status;
    NDIS_FILTER_DRIVER_CHARACTERISTICS	FChars;
    NDIS_STRING                         ServiceName;
    NDIS_STRING                         UniqueName;
    NDIS_STRING                         FriendlyName;
    NET_BUFFER_LIST_POOL_PARAMETERS		NetBufferListPoolParam;

    RtlInitUnicodeString(&ServiceName, L"natdrv6");
    RtlInitUnicodeString(&FriendlyName, L"NAT/Firewall Filter Driver");
    RtlInitUnicodeString(&UniqueName, L"natdrv6");
    FilterDriverObject = DriverObject;

    NdisZeroMemory(&FChars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
    FChars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    FChars.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
    FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
    FChars.MajorNdisVersion = 6;
    FChars.MinorNdisVersion = 0;
    FChars.MajorDriverVersion = 1;
    FChars.MinorDriverVersion = 0;
    FChars.Flags = 0;

    FChars.FriendlyName = FriendlyName;
    FChars.UniqueName = UniqueName;
    FChars.ServiceName = ServiceName;

    FChars.SetOptionsHandler = FilterRegisterOptions;
    FChars.AttachHandler = FilterAttach;
    FChars.DetachHandler = FilterDetach;
    FChars.RestartHandler = FilterRestart;
    FChars.PauseHandler = FilterPause;
    FChars.SetFilterModuleOptionsHandler = FilterSetModuleOptions;
    FChars.OidRequestHandler = FilterOidRequest;
    FChars.OidRequestCompleteHandler = FilterOidRequestComplete;
    FChars.CancelOidRequestHandler = FilterCancelOidRequest;

    FChars.SendNetBufferListsHandler = FilterSendNetBufferLists;
    FChars.ReturnNetBufferListsHandler = FilterReturnNetBufferLists;
    FChars.SendNetBufferListsCompleteHandler = FilterSendNetBufferListsComplete;
    FChars.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;
    FChars.DevicePnPEventNotifyHandler = FilterDevicePnPEventNotify;
    FChars.NetPnPEventHandler = FilterNetPnPEvent;
    FChars.StatusHandler = FilterStatus;
    FChars.CancelSendNetBufferListsHandler = FilterCancelSendNetBufferLists;

#pragma prefast(suppress:28175, "The <member> member of <struct> should not be accessed by a driver")
    DriverObject->DriverUnload = FilterUnload;

    FilterDriverHandle = NULL;

    NdisAllocateSpinLock(&g_AdapterListLock);
    InitializeListHead(&g_AdapterListHead);

    InitPacketLookaside();
    natInitTraced();
    natInitFwSession();
    natReadRegValues(RegistryPath);

    Status = NdisFRegisterFilterDriver(DriverObject,
        (NDIS_HANDLE)FilterDriverObject,
        &FChars,
        &FilterDriverHandle);
    if (Status != NDIS_STATUS_SUCCESS)
        goto finish;

    NetBufferListPoolParam.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    NetBufferListPoolParam.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    NetBufferListPoolParam.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    NetBufferListPoolParam.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    NetBufferListPoolParam.fAllocateNetBuffer = TRUE;
    NetBufferListPoolParam.ContextSize = 0;
    NetBufferListPoolParam.PoolTag = MODULE_TAG1;
    NetBufferListPoolParam.DataSize = 0;
    g_PoolNetBufferList = NdisAllocateNetBufferListPool(FilterDriverHandle, &NetBufferListPoolParam);
    if (g_PoolNetBufferList == NULL) {
        NdisFDeregisterFilterDriver(FilterDriverHandle);
        NdisFreeSpinLock(&g_AdapterListLock);
        goto finish;
    }

    Status = FilterRegisterDevice();
    if (Status != NDIS_STATUS_SUCCESS) {
        NdisFDeregisterFilterDriver(FilterDriverHandle);
        NdisFreeSpinLock(&g_AdapterListLock);
        goto finish;
    }

finish:

    if (NDIS_STATUS_SUCCESS != Status) {

        natDeinitFwSession();
        natReleaseTracedAll();
        ReleasePacketLookaside();

        if (g_PoolNetBufferList)
            NdisFreeNetBufferListPool(g_PoolNetBufferList);

        NdisFreeSpinLock(&g_AdapterListLock);
    }

    return Status;
}

NDIS_STATUS
FilterRegisterOptions(
    IN NDIS_HANDLE  NdisFilterDriverHandle,
    IN NDIS_HANDLE  FilterDriverContext
)
{
    ASSERT(NdisFilterDriverHandle == FilterDriverHandle);
    ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);

    if ((NdisFilterDriverHandle != (NDIS_HANDLE)FilterDriverHandle) ||
        (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject))
        return NDIS_STATUS_INVALID_PARAMETER;

    return NDIS_STATUS_SUCCESS;
}


NDIS_STATUS
FilterAttach(
    IN  NDIS_HANDLE                     NdisFilterHandle,
    IN  NDIS_HANDLE                     FilterDriverContext,
    IN  PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters
)
{
    PNETGW_ADAPT pAdapter = NULL;
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    NDIS_FILTER_ATTRIBUTES FilterAttributes;
    unsigned char szAdapterNameBuffer[512];
    ANSI_STRING szAdapterName;
    ULONG Size;

    szAdapterName.Buffer = (PCHAR)szAdapterNameBuffer;
    szAdapterName.Length = 0;
    szAdapterName.MaximumLength = sizeof(szAdapterNameBuffer);

    ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);
    if (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject) {
        Status = NDIS_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    Size = sizeof(NETGW_ADAPT) +
        AttachParameters->FilterModuleGuidName->Length +
        AttachParameters->BaseMiniportInstanceName->Length +
        AttachParameters->BaseMiniportName->Length;

    pAdapter = (PNETGW_ADAPT)NdisAllocateMemoryWithTagPriority(NdisFilterHandle, Size, FILTER_ALLOC_TAG, LowPoolPriority);
    if (pAdapter == NULL) {
        Status = NDIS_STATUS_RESOURCES;
        goto finish;
    }

    NdisZeroMemory(pAdapter, sizeof(NETGW_ADAPT));

    natInitControlBlock(&pAdapter->ctrl);

    pAdapter->m_Medium = AttachParameters->MiniportMediaType;

    pAdapter->FilterModuleName.Length = pAdapter->FilterModuleName.MaximumLength = AttachParameters->FilterModuleGuidName->Length;
    pAdapter->FilterModuleName.Buffer = (PWSTR)((PUCHAR)pAdapter + sizeof(NETGW_ADAPT));
    NdisMoveMemory(pAdapter->FilterModuleName.Buffer,
        AttachParameters->FilterModuleGuidName->Buffer,
        pAdapter->FilterModuleName.Length);

    pAdapter->MiniportFriendlyName.Length = pAdapter->MiniportFriendlyName.MaximumLength = AttachParameters->BaseMiniportInstanceName->Length;
    pAdapter->MiniportFriendlyName.Buffer = (PWSTR)((PUCHAR)pAdapter->FilterModuleName.Buffer + pAdapter->FilterModuleName.Length);
    NdisMoveMemory(pAdapter->MiniportFriendlyName.Buffer,
        AttachParameters->BaseMiniportInstanceName->Buffer,
        pAdapter->MiniportFriendlyName.Length);

    pAdapter->MiniportName.Length = pAdapter->MiniportName.MaximumLength = AttachParameters->BaseMiniportName->Length;
    pAdapter->MiniportName.Buffer = (PWSTR)((PUCHAR)pAdapter->MiniportFriendlyName.Buffer +
        pAdapter->MiniportFriendlyName.Length);
    NdisMoveMemory(pAdapter->MiniportName.Buffer,
        AttachParameters->BaseMiniportName->Buffer,
        pAdapter->MiniportName.Length);

    NdisUnicodeStringToAnsiString(
        &szAdapterName,
        &pAdapter->MiniportName
    );

    InitializeListHead(&pAdapter->m_WanLinksList);
    NdisAllocateSpinLock(&pAdapter->m_WanLinksLock);

    NdisMoveMemory(pAdapter->ctrl.MacAddr.Arr,
        AttachParameters->CurrentMacAddress,
        min(AttachParameters->MacAddressLength,
            sizeof(pAdapter->ctrl.MacAddr.Val)));

    pAdapter->MiniportIfIndex = AttachParameters->BaseMiniportIfIndex;
    pAdapter->FilterHandle = NdisFilterHandle;

    NdisZeroMemory(&FilterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
    FilterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    FilterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
    FilterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    FilterAttributes.Flags = 0;

    Status = NdisFSetAttributes(NdisFilterHandle,
        pAdapter,
        &FilterAttributes);
    if (Status != NDIS_STATUS_SUCCESS)
        goto finish;

    InterlockedExchange(&pAdapter->State, 0);

    NdisAcquireSpinLock(&g_AdapterListLock);
    InsertHeadList(&g_AdapterListHead, &pAdapter->ctrl.ListEntry);
    NdisReleaseSpinLock(&g_AdapterListLock);

finish:

    if (Status != NDIS_STATUS_SUCCESS)
    {
        if (pAdapter != NULL)
        {
            NdisFreeMemory(pAdapter, 0, 0);
        }
    }

    return Status;
}

NDIS_STATUS
FilterPause(
    IN  NDIS_HANDLE Context,
    IN  PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters
)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)(Context);
    NDIS_STATUS Status;
    LARGE_INTEGER WaitTime;

    UNREFERENCED_PARAMETER(PauseParameters);

    WaitTime.QuadPart = -(10000 * 15); // 15 ms

    ASSERT(pAdapter->State);

    Status = NDIS_STATUS_SUCCESS;

    InterlockedExchange(&pAdapter->State, 0);

    while (pAdapter->TRxPending > 0)
        KeDelayExecutionThread(KernelMode, FALSE, &WaitTime);

    ASSERT(pAdapter->TRxPending >= 0);

    return Status;
}

NDIS_STATUS
FilterRestart(
    IN  NDIS_HANDLE Context,
    IN  PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
)
{
    NDIS_STATUS	Status;
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)Context;
    NDIS_HANDLE	ConfigurationHandle = NULL;

    PNDIS_RESTART_GENERAL_ATTRIBUTES NdisGeneralAttributes;
    PNDIS_RESTART_ATTRIBUTES         NdisRestartAttributes;
    NDIS_CONFIGURATION_OBJECT        ConfigObject;

    ASSERT(!pAdapter->State);

    ConfigObject.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    ConfigObject.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    ConfigObject.Header.Size = sizeof(NDIS_CONFIGURATION_OBJECT);
    ConfigObject.NdisHandle = FilterDriverHandle;
    ConfigObject.Flags = 0;

    Status = NdisOpenConfigurationEx(&ConfigObject, &ConfigurationHandle);

    if (Status == NDIS_STATUS_SUCCESS)
        NdisCloseConfiguration(ConfigurationHandle);

    NdisRestartAttributes = RestartParameters->RestartAttributes;

    if (NdisRestartAttributes != NULL) {

        PNDIS_RESTART_ATTRIBUTES   NextAttributes;

        ASSERT(NdisRestartAttributes->Oid == OID_GEN_MINIPORT_RESTART_ATTRIBUTES);

        NdisGeneralAttributes = (PNDIS_RESTART_GENERAL_ATTRIBUTES)NdisRestartAttributes->Data;

        if (NdisGeneralAttributes->MtuSize > MAX_ETHER_SIZE)
            NdisGeneralAttributes->MtuSize = MAX_ETHER_SIZE;

        pAdapter->m_usMTU = NdisGeneralAttributes->MtuSize;

        NdisGeneralAttributes->LookaheadSize = 128;

        NextAttributes = NdisRestartAttributes->Next;

        pAdapter->m_OffloadParam.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        pAdapter->m_OffloadParam.Header.Revision = NDIS_OFFLOAD_PARAMETERS_REVISION_1;
        pAdapter->m_OffloadParam.Header.Size = NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_1;

        pAdapter->m_OffloadParam.IPv4Checksum = NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED;
        pAdapter->m_OffloadParam.TCPIPv4Checksum = NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED;
        pAdapter->m_OffloadParam.UDPIPv4Checksum = NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED;
        pAdapter->m_OffloadParam.TCPIPv6Checksum = NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED;
        pAdapter->m_OffloadParam.UDPIPv6Checksum = NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED;
        pAdapter->m_OffloadParam.LsoV1 = NDIS_OFFLOAD_PARAMETERS_LSOV1_DISABLED;
        pAdapter->m_OffloadParam.IPsecV1 = NDIS_OFFLOAD_PARAMETERS_IPSECV1_DISABLED;
        pAdapter->m_OffloadParam.LsoV2IPv4 = NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED;
        pAdapter->m_OffloadParam.LsoV2IPv6 = NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED;
        pAdapter->m_OffloadParam.TcpConnectionIPv4 = NDIS_OFFLOAD_PARAMETERS_NO_CHANGE;
        pAdapter->m_OffloadParam.TcpConnectionIPv6 = NDIS_OFFLOAD_PARAMETERS_NO_CHANGE;
        pAdapter->m_OffloadParam.Flags = 0;

        FilterDoInternalRequest(
            pAdapter,
            NdisRequestSetInformation,
            OID_TCP_OFFLOAD_PARAMETERS,
            &pAdapter->m_OffloadParam,
            sizeof(pAdapter->m_OffloadParam),
            sizeof(pAdapter->m_OffloadParam)
        );
    }

    InterlockedExchange(&pAdapter->State, 1);
    Status = NDIS_STATUS_SUCCESS;
    return Status;
}

VOID
FilterDetach(
    IN  NDIS_HANDLE Context
)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)Context;

    NdisAcquireSpinLock(&g_AdapterListLock);
    RemoveEntryList(&pAdapter->ctrl.ListEntry);
    NdisReleaseSpinLock(&g_AdapterListLock);

    natFreeAllItems(&pAdapter->ctrl);
    natFreeAllFwSessionsAndRules(&pAdapter->ctrl);

    NdisFreeMemory(pAdapter, 0, 0);
}

VOID
FilterUnload(
    IN  PDRIVER_OBJECT      driverObject
)
{
    UNREFERENCED_PARAMETER(driverObject);

    natDeinitFwSession();
    natReleaseTracedAll();

    FilterDeregisterDevice();
    NdisFDeregisterFilterDriver(FilterDriverHandle);

    if (g_PoolNetBufferList)
        NdisFreeNetBufferListPool(g_PoolNetBufferList);

    NdisFreeSpinLock(&g_AdapterListLock);

    ReleasePacketLookaside();
}

VOID
FilterStatus(
    IN  NDIS_HANDLE             Context,
    IN  PNDIS_STATUS_INDICATION StatusIndication
)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)Context;
    NDIS_STATUS GeneralStatus = StatusIndication->StatusCode;
    PVOID StatusBuffer = StatusIndication->StatusBuffer;
    PNDIS_WWAN_CONTEXT_STATE pContextState = NULL;
    PNDIS_WAN_LINE_UP pLineUp = NULL;
    PNDIS_WAN_LINE_DOWN pLineDown = NULL;

    switch (GeneralStatus) {
        case NDIS_STATUS_WAN_LINE_UP:

        pLineUp = (PNDIS_WAN_LINE_UP)StatusBuffer;

        NdisMoveMemory(
            pAdapter->m_RemoteAddress,
            pLineUp->RemoteAddress,
            ETHER_ADDR_LEN
        );

        pAdapter->m_usMTU = (USHORT)pLineUp->MaximumTotalSize;
        pLineUp->MaximumTotalSize = pLineUp->MaximumTotalSize;
        break;

        case NDIS_STATUS_WAN_LINE_DOWN:

        pLineDown = (PNDIS_WAN_LINE_DOWN)StatusBuffer;
        NdisZeroMemory(
            pAdapter->m_RemoteAddress,
            ETHER_ADDR_LEN
        );

        NdisZeroMemory(
            pAdapter->m_LocalAddress,
            ETHER_ADDR_LEN
        );
        break;

        case NDIS_STATUS_WWAN_CONTEXT_STATE:

        pContextState = (PNDIS_WWAN_CONTEXT_STATE)StatusBuffer;

        switch (pContextState->ContextState.ActivationState) {
            case WwanActivationStateActivated:
            break;
            case WwanActivationStateDeactivated:

            if (WWAN_STATUS_SUCCESS != pContextState->uStatus)
                break;

            NdisZeroMemory(
                pAdapter->m_LocalAddress,
                ETHER_ADDR_LEN
            );

            break;
        }
        break;
    }

    NdisFIndicateStatus(pAdapter->FilterHandle, StatusIndication);

    switch (GeneralStatus) {
        case NDIS_STATUS_WAN_LINE_UP:

        NdisMoveMemory(
            pAdapter->m_LocalAddress,
            pLineUp->LocalAddress,
            ETHER_ADDR_LEN
        );
        break;

        case NDIS_STATUS_WWAN_CONTEXT_STATE:

        pContextState = (PNDIS_WWAN_CONTEXT_STATE)StatusBuffer;

        switch (pContextState->ContextState.ActivationState) {
            case WwanActivationStateActivated:

            if (WWAN_STATUS_SUCCESS != pContextState->uStatus)
                break;

            NdisMoveMemory(
                &pAdapter->m_LocalAddress[2],
                &pContextState->ContextState.ConnectionId,
                sizeof(ULONG)
            );

            break;
            case WwanActivationStateDeactivated:
            break;

        }
    }
}

VOID
FilterDevicePnPEventNotify(
    IN  NDIS_HANDLE             Context,
    IN  PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
)
{
    PNETGW_ADAPT          pAdapter = (PNETGW_ADAPT)Context;
    NDIS_DEVICE_PNP_EVENT   DevicePnPEvent = NetDevicePnPEvent->DevicePnPEvent;

    switch (DevicePnPEvent) {
        case NdisDevicePnPEventQueryRemoved:
        case NdisDevicePnPEventRemoved:
        case NdisDevicePnPEventSurpriseRemoved:
        case NdisDevicePnPEventQueryStopped:
        case NdisDevicePnPEventStopped:
        case NdisDevicePnPEventPowerProfileChanged:
        case NdisDevicePnPEventFilterListChanged:
        break;
        default:
        ASSERT(FALSE);
        break;
    }

    NdisFDevicePnPEventNotify(pAdapter->FilterHandle, NetDevicePnPEvent);
}


NDIS_STATUS
FilterNetPnPEvent(
    IN  NDIS_HANDLE             Context,
    IN  PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification
)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)Context;
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;

    Status = NdisFNetPnPEvent(pAdapter->FilterHandle, NetPnPEventNotification);

    return Status;
}


VOID FilterFreeNetBufferList(PNET_BUFFER_LIST pNBList, BOOLEAN bFreeMdl)
{
    PNET_BUFFER pNBuf, pCurNBuf;
    PMDL pMdl = NULL, pCurrMdl = NULL;

    if (NULL == pNBList)
        return;

    ASSERT(NULL == pNBList->Next);

    if (bFreeMdl) {

        pNBuf = NET_BUFFER_LIST_FIRST_NB(pNBList);
        while (pNBuf != NULL) {

            pCurNBuf = pNBuf;
            pNBuf = NET_BUFFER_NEXT_NB(pNBuf);

            ASSERT(NET_BUFFER_CURRENT_MDL(pCurNBuf) == NET_BUFFER_FIRST_MDL(pCurNBuf));

            pMdl = NET_BUFFER_CURRENT_MDL(pCurNBuf);
            while (pMdl != NULL) {
                pCurrMdl = pMdl;
                pMdl = pMdl->Next;
                NdisFreeMdl(pCurrMdl);
            }
        }
    }

    NdisFreeNetBufferList(pNBList);
}

VOID
FilterSendNetBufferListsComplete(
    IN  NDIS_HANDLE         Context,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               SendCompleteFlags
)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)Context;
    PNET_BUFFER_LIST pCurList = NULL;
    PNET_BUFFER_LIST_CONTEXT pContext;
    FLT_PKT_CTX* pFltContext;
    FLT_PKT* pFltPkt;

    while (NetBufferLists != NULL) {

        pCurList = NetBufferLists;
        NetBufferLists = NET_BUFFER_LIST_NEXT_NBL(NetBufferLists);
        pCurList->Next = NULL;

        if (pCurList->NdisPoolHandle != g_PoolNetBufferList) {

            NdisFSendNetBufferListsComplete(pAdapter->FilterHandle, pCurList, SendCompleteFlags);
            continue;
        }

        pFltPkt = NULL;
        for (pContext = pCurList->Context; pContext != NULL; pContext = pContext->Next) {

            if (pContext->Size != sizeof(FLT_PKT_CTX))
                continue;
            pFltContext = (FLT_PKT_CTX*)(pContext + 1);
            if (pFltContext->Signature != 'eNwG')
                continue;
            if (pFltContext->Size != pContext->Size)
                continue;

            pFltPkt = pFltContext->pFltPkt;
            if (pFltPkt == NULL)
                continue;
            break;
        }

        if (pFltPkt == NULL) {
            InterlockedDecrement(&pAdapter->TRxPending);
            continue;
        }

        FilterFreeNetBufferList(pCurList, NULL != pFltPkt->pBuf);
        FreeFltPkt(pFltPkt);
        InterlockedDecrement(&pAdapter->TRxPending);
    }
}


#define MAX_PACKETS 64

VOID
FilterSendNetBufferLists(
    IN  NDIS_HANDLE         Context,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               SendFlags
)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)Context;
    PNET_BUFFER_LIST pCurList = NULL, pList2Send = NULL;
    BOOLEAN	bDispatchLevel;
    PNET_BUFFER_LIST pFirstList2Send = NULL, pPrevList2Send = NULL;
    ULONG uLists2Send = 0;

    bDispatchLevel = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags);

    if (1 > InterlockedCompareExchange(&pAdapter->State, 1, 1)) {

        for (pCurList = NetBufferLists;
            pCurList != NULL;
            pCurList = NET_BUFFER_LIST_NEXT_NBL(pCurList))
        {
            NET_BUFFER_LIST_STATUS(pCurList) = NDIS_STATUS_PAUSED;
        }

        if (NetBufferLists)
            NdisFSendNetBufferListsComplete(pAdapter->FilterHandle, NetBufferLists, bDispatchLevel ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
        return;
    }

    pCurList = NetBufferLists;

    while (pCurList != NULL) {

        pList2Send = pCurList;
        pCurList = NET_BUFFER_LIST_NEXT_NBL(pCurList);
        pList2Send->Next = NULL;

        if (!filterSendReceiveNBL(pAdapter, pList2Send, PortNumber, SendFlags, TRUE)) {
            NdisFSendNetBufferListsComplete(pAdapter->FilterHandle, pList2Send, bDispatchLevel ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
        }
        else {
            if (pFirstList2Send == NULL)
                pFirstList2Send = pList2Send;

            if (pPrevList2Send != NULL)
                pPrevList2Send->Next = pList2Send;

            pPrevList2Send = pList2Send;
            uLists2Send++;
        }
    }

    if (uLists2Send)
        NdisFSendNetBufferLists(pAdapter->FilterHandle, pFirstList2Send, PortNumber, SendFlags);
}

BOOLEAN
filterSendReceiveNBL(
    IN PNETGW_ADAPT pAdapter,
    IN PNET_BUFFER_LIST  pNBL,
    IN NDIS_PORT_NUMBER PortNumber,
    IN ULONG Flags,
    IN BOOLEAN bSend
)
{
    PNET_BUFFER pNB;
    BOOLEAN processImmediately = FALSE;
    BOOLEAN dropAll = FALSE;
    FLT_PKT* pFltPkt;
    FLT_PKT* pFirstFltPkt = NULL, *pPrevFltPkt = NULL;
    PNET_BUFFER_LIST pNBList = NULL;
    PNET_BUFFER_LIST pFirstList = NULL, pPrevList = NULL;
    ULONG uLists = 0;

    for (pNB = NET_BUFFER_LIST_FIRST_NB(pNBL);
        pNB;
        pNB = NET_BUFFER_NEXT_NB(pNB)) {

        pFltPkt = AllocateFltPacket();
        if (NULL == pFltPkt) {

            dropAll = TRUE;
            processImmediately = FALSE;
            break;
        }

        if (!natbParsePacket(pNB, pFltPkt)) {

            if (g_LogPktDrop) PrintFtlPkt("DROP (failed to parse)", pFltPkt, 0, bSend);

            FreeFltPkt(pFltPkt);
            dropAll = TRUE;
            processImmediately = FALSE;
            break;
        }

        if (bSend) {

            if (!FilterPkt(&pAdapter->ctrl, pFltPkt, bSend)) {

                if (g_LogPktDrop)
                    PrintFtlPkt("DROP- ", pFltPkt, 0, bSend);

                FreeFltPkt(pFltPkt);
                dropAll = TRUE;
                processImmediately = FALSE;
                break;
            }

            TranslatePktOutgoing(&pAdapter->ctrl, pFltPkt);

        }
        else {

            TranslatePktIncoming(&pAdapter->ctrl, pFltPkt);

            if (!FilterPkt(&pAdapter->ctrl, pFltPkt, bSend)) {

                if (g_LogPktDrop)
                    PrintFtlPkt("DROP ", pFltPkt, 0, bSend);

                FreeFltPkt(pFltPkt);
                dropAll = TRUE;
                processImmediately = FALSE;
                break;
            }
        }

        if (pPrevFltPkt)
            pPrevFltPkt->pNext = pFltPkt;
        else
            pFirstFltPkt = pFltPkt;

        pPrevFltPkt = pFltPkt;

        if (pFltPkt->pBuf)
            processImmediately = TRUE;
    }

    for (pFltPkt = pFirstFltPkt; pFltPkt; pFltPkt = pPrevFltPkt) {

        pNBList = NULL;

        if (dropAll) {
            if (g_LogPktDrop)
                PrintFtlPkt("DROP+ ", pFltPkt, 0, bSend);
        }
        else {
            if (g_LogPktPass) PrintFtlPkt(processImmediately ? "PASS+ " : "PASS ", pFltPkt, 0, bSend);
        }

        if (processImmediately)
            pNBList = filterGetNewNetBufferList(pFltPkt, pAdapter);

        pPrevFltPkt = pFltPkt->pNext;

        if (pNBList) {

            if (pPrevList)
                pPrevList->Next = pNBList;
            else
                pFirstList = pNBList;

            pPrevList = pNBList;

            uLists++;
            InterlockedIncrement(&pAdapter->TRxPending);

        }
        else
            FreeFltPkt(pFltPkt);
    }

    if (uLists) {

        if (bSend)
            NdisFSendNetBufferLists(pAdapter->FilterHandle, pFirstList, PortNumber, Flags);
        else
            NdisFIndicateReceiveNetBufferLists(pAdapter->FilterHandle, pFirstList, PortNumber, uLists, Flags);
    }

    return !processImmediately && !dropAll;
}


VOID
FilterReturnNetBufferLists(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               ReturnFlags
)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)FilterModuleContext;
    PNET_BUFFER_LIST pCurList = NULL;
    PNET_BUFFER_LIST_CONTEXT pContext;
    FLT_PKT_CTX* pFltContext;
    FLT_PKT* pFltPkt;

    while (NetBufferLists != NULL) {

        pCurList = NetBufferLists;
        NetBufferLists = NET_BUFFER_LIST_NEXT_NBL(NetBufferLists);
        pCurList->Next = NULL;

        if (g_PoolNetBufferList != pCurList->NdisPoolHandle) {
            NdisFReturnNetBufferLists(pAdapter->FilterHandle, pCurList, ReturnFlags);
            continue;
        }

        pFltPkt = NULL;
        for (pContext = pCurList->Context; pContext != NULL; pContext = pContext->Next) {

            if (pContext->Size != sizeof(FLT_PKT_CTX))
                continue;
            pFltContext = (FLT_PKT_CTX*)(pContext + 1);
            if (pFltContext->Signature != 'eNwG')
                continue;
            if (pFltContext->Size != pContext->Size)
                continue;

            pFltPkt = pFltContext->pFltPkt;
            if (pFltPkt == NULL)
                continue;
            break;
        }

        if (NULL == pFltPkt) {
            InterlockedDecrement(&pAdapter->TRxPending);
            continue;
        }

        FilterFreeNetBufferList(pCurList, NULL != pFltPkt->pBuf);
        FreeFltPkt(pFltPkt);
        InterlockedDecrement(&pAdapter->TRxPending);
    }
}

VOID
FilterReceiveNetBufferLists(
    IN  NDIS_HANDLE         Context,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               NumberOfNetBufferLists,
    IN  ULONG               ReceiveFlags
)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)Context;
    BOOLEAN	bDispatchLevel, bResources;
    PNET_BUFFER_LIST pCurList = NULL, pNBListToRcv = NULL;
    PNET_BUFFER_LIST pFirstNblToRcv = NULL, pPrevNblToRcv = NULL;
    ULONG uNBListCount = 0;

    UNREFERENCED_PARAMETER(NumberOfNetBufferLists);

    bResources = NDIS_TEST_RECEIVE_FLAG(ReceiveFlags, NDIS_RECEIVE_FLAGS_RESOURCES);

    bDispatchLevel = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags);

    ASSERT(NumberOfNetBufferLists >= 1);

    if (1 > InterlockedCompareExchange(&pAdapter->State, 1, 1)) {

        if (!bResources)
            NdisFReturnNetBufferLists(pAdapter->FilterHandle, NetBufferLists, bDispatchLevel);
        return;
    }

    if (bResources) {

        for (pCurList = NetBufferLists; pCurList; pCurList = NET_BUFFER_LIST_NEXT_NBL(pCurList)) {

            if (filterSendReceiveNBL(pAdapter, pCurList, PortNumber, ReceiveFlags, FALSE)) {

                pNBListToRcv = NET_BUFFER_LIST_NEXT_NBL(pCurList);
                NET_BUFFER_LIST_NEXT_NBL(pCurList) = NULL;

                NdisFIndicateReceiveNetBufferLists(pAdapter->FilterHandle, pCurList, PortNumber, 1, ReceiveFlags);

                NET_BUFFER_LIST_NEXT_NBL(pCurList) = pNBListToRcv;
            }
        }
        return;
    }

    for (pCurList = NetBufferLists; pCurList != NULL;) {

        pNBListToRcv = pCurList;
        pCurList = NET_BUFFER_LIST_NEXT_NBL(pCurList);
        pNBListToRcv->Next = NULL;

        if (filterSendReceiveNBL(pAdapter, pNBListToRcv, PortNumber, ReceiveFlags, FALSE)) {

            uNBListCount++;

            if (pPrevNblToRcv)
                pPrevNblToRcv->Next = pNBListToRcv;
            else
                pFirstNblToRcv = pNBListToRcv;

            pPrevNblToRcv = pNBListToRcv;

        }
        else {

            NdisFReturnNetBufferLists(pAdapter->FilterHandle, pNBListToRcv, bDispatchLevel);
        }
    }

    if (uNBListCount) {
        NdisFIndicateReceiveNetBufferLists(pAdapter->FilterHandle, pFirstNblToRcv, PortNumber, uNBListCount, ReceiveFlags);
    }
}

VOID
FilterCancelSendNetBufferLists(
    IN  NDIS_HANDLE             Context,
    IN  PVOID                   CancelId
)
{
    PNETGW_ADAPT  pAdapter = (PNETGW_ADAPT)Context;
    NdisFCancelSendNetBufferLists(pAdapter->FilterHandle, CancelId);
}

NDIS_STATUS
FilterSetModuleOptions(
    IN  NDIS_HANDLE             Context
)
{
    UNREFERENCED_PARAMETER(Context);
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
natmSendFltPacket(
    IN PFILTER_COMMON_CONTROL_BLOCK pAdaptControl,
    IN FLT_PKT* pFltPkt
)
{
    UNREFERENCED_PARAMETER(pAdaptControl);
    UNREFERENCED_PARAMETER(pFltPkt);
    return NDIS_STATUS_SUCCESS;
}
