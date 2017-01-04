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

#define MAX_PACKET_POOL_SIZE 0x0000FFFF
#define MIN_PACKET_POOL_SIZE 0x000000FF

#define UPPER_BINDINGS	NDIS_STRING_CONST("UpperBindings")

int
natpReceivePacketPassThrough(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_PACKET	Packet,
    IN FLT_PKT* pFltPkt
);

VOID
natpFlushReceiveQueue(
    IN PFILTER_ADAPTER pAdapt
);

VOID
natpQueueReceivedPacket(
    IN PFILTER_ADAPTER pAdapt,
    IN PNDIS_PACKET Packet,
    IN BOOLEAN DoIndicate
);

VOID
StartQueryInfo(
    IN PFILTER_ADAPTER pAdapter
);

NAT_ENTRY *alpha_entry;

VOID
natpBindAdapter(
    OUT PNDIS_STATUS Status,
    IN  NDIS_HANDLE BindContext,
    IN  PNDIS_STRING DeviceName,
    IN  PVOID SystemSpecific1,
    IN  PVOID SystemSpecific2
)
{
    NDIS_HANDLE ConfigHandle = NULL;
    PNDIS_CONFIGURATION_PARAMETER Param;
    NDIS_STRING DeviceStr = UPPER_BINDINGS;
    PFILTER_ADAPTER pAdapt = NULL;
    NDIS_STATUS Sts;
    UINT MediumIndex, i;
    ULONG TotalSize;
    WCHAR DevicePrefix[] = L"\\Device\\";

    UNREFERENCED_PARAMETER(BindContext);
    UNREFERENCED_PARAMETER(SystemSpecific2);

    __try {

        NdisOpenProtocolConfiguration(
            Status,
            &ConfigHandle,
            SystemSpecific1
        );

        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;

        NdisReadConfiguration(
            Status,
            &Param,
            ConfigHandle,
            &DeviceStr,
            NdisParameterString
        );
        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;

        TotalSize = sizeof(FILTER_ADAPTER) + Param->ParameterData.StringData.MaximumLength + DeviceName->MaximumLength;
        NdisAllocateMemoryWithTag(&pAdapt, TotalSize, NAT_TAG);

        if (NULL == pAdapt) {
            *Status = NDIS_STATUS_RESOURCES;
            __leave;
        }


        NdisZeroMemory(pAdapt, TotalSize);
        pAdapt->DeviceName.MaximumLength = Param->ParameterData.StringData.MaximumLength;
        pAdapt->DeviceName.Length = Param->ParameterData.StringData.Length;
        pAdapt->DeviceName.Buffer = (PWCHAR)((ULONG_PTR)pAdapt + sizeof(FILTER_ADAPTER));
        NdisMoveMemory(
            pAdapt->DeviceName.Buffer,
            Param->ParameterData.StringData.Buffer,
            Param->ParameterData.StringData.MaximumLength
        );
        if (sizeof(DevicePrefix) >= DeviceName->Length) {


        }
        else {

            pAdapt->RootDeviceName.MaximumLength = DeviceName->MaximumLength;
            pAdapt->RootDeviceName.Length = DeviceName->Length - sizeof(DevicePrefix) + sizeof(WCHAR);
            pAdapt->RootDeviceName.Buffer = (PWCHAR)((ULONG_PTR)pAdapt + sizeof(FILTER_ADAPTER) + Param->ParameterData.StringData.MaximumLength);
            NdisMoveMemory(
                pAdapt->RootDeviceName.Buffer,
                DeviceName->Buffer + sizeof(DevicePrefix) / sizeof(WCHAR) - 1,
                DeviceName->MaximumLength - sizeof(DevicePrefix) / sizeof(WCHAR) + 1
            );
        }

        NdisInitializeEvent(&pAdapt->Event);
        NdisAllocateSpinLock(&pAdapt->Lock);

        natInitControlBlock(&pAdapt->ctrl);

        NdisAllocatePacketPoolEx(
            Status,
            &pAdapt->SndPP1,
            MIN_PACKET_POOL_SIZE,
            MAX_PACKET_POOL_SIZE,
            PROTOCOL_RESERVED_SIZE_IN_PACKET
        );

        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;

        NdisAllocatePacketPoolEx(
            Status,
            &pAdapt->SndPP2,
            MIN_PACKET_POOL_SIZE,
            MAX_PACKET_POOL_SIZE,
            PROTOCOL_RESERVED_SIZE_IN_PACKET
        );

        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;

        NdisAllocateBufferPool(
            Status,
            &pAdapt->SndBP,
            MIN_PACKET_POOL_SIZE
        );
        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;

        NdisAllocatePacketPoolEx(
            Status,
            &pAdapt->RcvPP1,
            MIN_PACKET_POOL_SIZE,
            MAX_PACKET_POOL_SIZE - MIN_PACKET_POOL_SIZE,
            PROTOCOL_RESERVED_SIZE_IN_PACKET
        );

        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;

        NdisAllocatePacketPoolEx(
            Status,
            &pAdapt->RcvPP2,
            MIN_PACKET_POOL_SIZE,
            MAX_PACKET_POOL_SIZE - MIN_PACKET_POOL_SIZE,
            PROTOCOL_RESERVED_SIZE_IN_PACKET
        );

        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;

        NdisAllocateBufferPool(
            Status,
            &pAdapt->RcvBP,
            MIN_PACKET_POOL_SIZE
        );
        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;

        NdisOpenAdapter(
            Status,
            &Sts,
            &pAdapt->BindingHandle,
            &MediumIndex,
            MediumArray,
            sizeof(MediumArray) / sizeof(NDIS_MEDIUM),
            ProtHandle,
            pAdapt,
            DeviceName,
            0, NULL
        );

        if (*Status == NDIS_STATUS_PENDING) {
            NdisWaitEvent(&pAdapt->Event, 0);
            *Status = pAdapt->Status;
        }

        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;
        pAdapt->Medium = MediumArray[MediumIndex];

        pAdapt->MiniportInitPending = TRUE;
        NdisInitializeEvent(&pAdapt->MiniportInitEvent);

        *Status =
            NdisIMInitializeDeviceInstanceEx(
                DriverHandle,
                &pAdapt->DeviceName,
                pAdapt
            );

        if (*Status != NDIS_STATUS_SUCCESS)
            __leave;
        StartQueryInfo(pAdapt);

    }
    __finally {
    }

    if (ConfigHandle != NULL)
        NdisCloseConfiguration(ConfigHandle);

    if (NDIS_STATUS_SUCCESS != *Status) {

        if (pAdapt != NULL) {

            if (pAdapt->BindingHandle != NULL) {

                NDIS_STATUS    LocalStatus;

                NdisResetEvent(&pAdapt->Event);

                NdisCloseAdapter(&LocalStatus, pAdapt->BindingHandle);
                pAdapt->BindingHandle = NULL;

                if (LocalStatus == NDIS_STATUS_PENDING) {
                    NdisWaitEvent(&pAdapt->Event, 0);
                    LocalStatus = pAdapt->Status;
                }
            }

            natFreeAllItems(&pAdapt->ctrl);
            natFreeAllFwSessionsAndRules(&pAdapt->ctrl);

            for (i = 0; i < FLT_FW_SESSION_HASH_TBL_SZ; i++)
                NdisFreeSpinLock(pAdapt->ctrl.FwSessionLocks + i);

            NdisFreeSpinLock(&pAdapt->ctrl.IcmpRuleLock);
            NdisFreeSpinLock(&pAdapt->ctrl.UdpRuleLock);
            NdisFreeSpinLock(&pAdapt->ctrl.TcpRuleLock);

            natmFreeAllPacketPools(pAdapt);

            NdisFreeSpinLock(&pAdapt->Lock);

            NdisFreeMemory(pAdapt, 0, 0);
            pAdapt = NULL;
        }
    }
}


VOID
natpOpenAdapterComplete(
    IN  NDIS_HANDLE	ProtocolBindingContext,
    IN  NDIS_STATUS	Status,
    IN  NDIS_STATUS	OpenErrorStatus
)
{
    PFILTER_ADAPTER	pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    UNREFERENCED_PARAMETER(OpenErrorStatus);

    pAdapt->Status = Status;
    NdisSetEvent(&pAdapt->Event);
}


VOID
natpUnbindAdapter(
    OUT PNDIS_STATUS Status,
    IN  NDIS_HANDLE ProtocolBindingContext,
    IN  NDIS_HANDLE UnbindContext
)
{
    PFILTER_ADAPTER	pAdapt;
    NDIS_STATUS	LocalStatus;

    pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    UNREFERENCED_PARAMETER(UnbindContext);

    NdisAcquireSpinLock(&pAdapt->Lock);
    pAdapt->UnbindingInProcess = TRUE;
    if (pAdapt->QueuedRequest == TRUE) {
        pAdapt->QueuedRequest = FALSE;
        NdisReleaseSpinLock(&pAdapt->Lock);

        natpRequestComplete(pAdapt,
            &pAdapt->IntReq.NdisRequest,
            NDIS_STATUS_FAILURE);

    }
    else {
        NdisReleaseSpinLock(&pAdapt->Lock);
    }

    if (pAdapt->MiniportInitPending == TRUE) {
        LocalStatus =
            NdisIMCancelInitializeDeviceInstance(
                DriverHandle,
                &pAdapt->DeviceName
            );

        if (LocalStatus == NDIS_STATUS_SUCCESS) {
            pAdapt->MiniportInitPending = FALSE;
            ASSERT(pAdapt->MiniportHandle == NULL);

        }
        else {

            NdisWaitEvent(&pAdapt->MiniportInitEvent, 0);
            ASSERT(pAdapt->MiniportInitPending == FALSE);
        }
    }

    if (pAdapt->MiniportHandle != NULL) {
        *Status =
            NdisIMDeInitializeDeviceInstance(
                pAdapt->MiniportHandle
            );

        if (*Status != NDIS_STATUS_SUCCESS)
            *Status = NDIS_STATUS_FAILURE;
    }
    else {

        if (NULL != pAdapt->BindingHandle) {

            NdisResetEvent(&pAdapt->Event);
            NdisCloseAdapter(Status, pAdapt->BindingHandle);

            if (*Status == NDIS_STATUS_PENDING) {

                NdisWaitEvent(&pAdapt->Event, 0);
                *Status = pAdapt->Status;
            }
            pAdapt->BindingHandle = NULL;

        }
        else {
            *Status = NDIS_STATUS_FAILURE;
        }

        natFreeAllItems(&pAdapt->ctrl);
        natFreeAllFwSessionsAndRules(&pAdapt->ctrl);

        natmFreeAllPacketPools(pAdapt);

        if (pAdapt)
            NdisFreeSpinLock(&pAdapt->Lock);

        NdisFreeMemory(pAdapt, 0, 0);
    }

}

VOID
natpUnloadProtocol(
    VOID
)
{
    NDIS_STATUS Status;

    if (ProtHandle != NULL) {
        NdisDeregisterProtocol(&Status, ProtHandle);
        ProtHandle = NULL;
    }
}

VOID
natpCloseAdapterComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS Status
)
{
    PFILTER_ADAPTER	pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    pAdapt->Status = Status;
    NdisSetEvent(&pAdapt->Event);
}

VOID
natpResetComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS Status
)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(Status);
}


VOID
natpRequestComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_REQUEST NdisRequest,
    IN NDIS_STATUS Status
)
{
    PINTERNAL_REQUEST pIntReq;
    PFILTER_ADAPTER pAdapt;
    NDIS_OID Oid;

    pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    Oid = pAdapt->IntReq.NdisRequest.DATA.SET_INFORMATION.Oid;

    pIntReq = CONTAINING_RECORD(NdisRequest, INTERNAL_REQUEST, NdisRequest);
    pIntReq->nRequestStatus = Status;

    if (NT_SUCCESS(Status)) {

        if (NdisRequest->DATA.QUERY_INFORMATION.BytesWritten >
            NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength)
        {
            NdisRequest->DATA.QUERY_INFORMATION.BytesWritten =
                NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;
        }
    }

    if (pIntReq->bLocalRequest) {

        if (pIntReq->pLocalCompletionFunc) {

            (*pIntReq->pLocalCompletionFunc)(
                pAdapt,
                pIntReq,
                Status
                );
        }

        pAdapt->LocalOutstandingRequests = FALSE;
        return;
    }

    pAdapt->OutstandingRequests = FALSE;

    switch (NdisRequest->RequestType) {
    case NdisRequestQueryInformation:

        if ((Oid == OID_PNP_CAPABILITIES) && (Status == NDIS_STATUS_SUCCESS))
        {
            natmQueryPNPCapabilities(pAdapt, &Status);
        }
        *pAdapt->BytesReadOrWritten = NdisRequest->DATA.QUERY_INFORMATION.BytesWritten;
        *pAdapt->BytesNeeded = NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded;

        if ((Oid == OID_GEN_MAC_OPTIONS) && (Status == NDIS_STATUS_SUCCESS))
            *(PULONG)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer &= ~NDIS_MAC_OPTION_NO_LOOPBACK;


        if ((Oid == OID_802_3_CURRENT_ADDRESS) && (Status == NDIS_STATUS_SUCCESS))
            RtlCopyMemory(pAdapt->ctrl.MacAddr.Arr, NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer, 6);

        if (OID_TCP_TASK_OFFLOAD == Oid)
            Status = NDIS_STATUS_NOT_SUPPORTED;

        NdisMQueryInformationComplete(pAdapt->MiniportHandle, Status);
        break;

    case NdisRequestSetInformation:

        *pAdapt->BytesReadOrWritten = NdisRequest->DATA.SET_INFORMATION.BytesRead;
        *pAdapt->BytesNeeded = NdisRequest->DATA.SET_INFORMATION.BytesNeeded;

        if (OID_TCP_TASK_OFFLOAD == Oid)
            Status = NDIS_STATUS_NOT_SUPPORTED;

        NdisMSetInformationComplete(pAdapt->MiniportHandle, Status);
        break;

    default:
        break;
    }
}


VOID
natpStatus(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS GeneralStatus,
    IN PVOID StatusBuffer,
    IN UINT StatusBufferSize
)
{
    PFILTER_ADAPTER	pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    if ((pAdapt->MiniportHandle != NULL) &&
        (pAdapt->natpDeviceState == NdisDeviceStateD0) &&
        (pAdapt->natmDeviceState == NdisDeviceStateD0))
    {
        if ((GeneralStatus == NDIS_STATUS_MEDIA_CONNECT) ||
            (GeneralStatus == NDIS_STATUS_MEDIA_DISCONNECT))
        {

            pAdapt->LastIndicatedStatus = GeneralStatus;
        }
        NdisMIndicateStatus(pAdapt->MiniportHandle,
            GeneralStatus,
            StatusBuffer,
            StatusBufferSize);
    }
    else {

        if ((pAdapt->MiniportHandle != NULL) &&
            ((GeneralStatus == NDIS_STATUS_MEDIA_CONNECT) ||
            (GeneralStatus == NDIS_STATUS_MEDIA_DISCONNECT)))
        {
            pAdapt->LatestUnIndicateStatus = GeneralStatus;
        }
    }
}

VOID
natpStatusComplete(
    IN NDIS_HANDLE	ProtocolBindingContext
)
{
    PFILTER_ADAPTER pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    if ((pAdapt->MiniportHandle != NULL) &&
        (pAdapt->natpDeviceState == NdisDeviceStateD0) &&
        (pAdapt->natmDeviceState == NdisDeviceStateD0))
        NdisMIndicateStatusComplete(pAdapt->MiniportHandle);
}

VOID
natpSendComplete(
    IN  NDIS_HANDLE		ProtocolBindingContext,
    IN  PNDIS_PACKET	Packet,
    IN  NDIS_STATUS		Status
)
{
    PFILTER_ADAPTER	pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;
    PNDIS_PACKET pOrgPacket;
    NDIS_HANDLE PoolHandle;

    PoolHandle = NdisGetPoolFromPacket(Packet);

    if (PoolHandle == pAdapt->SndPP1) {

        pOrgPacket = *(PVOID*)(Packet->ProtocolReserved);

        NdisIMCopySendCompletePerPacketInfo(pOrgPacket, Packet);
        NdisDprFreePacket(Packet);

        NdisMSendComplete(
            pAdapt->MiniportHandle,
            pOrgPacket,
            Status
        );

    }
    else if (PoolHandle == pAdapt->SndPP2) {

        FLT_PKT *pFltPkt = *(PVOID*)(Packet->ProtocolReserved);

        ASSERT(pFltPkt);

        pOrgPacket = pFltPkt->pOrgPkt;

        natmFreeBuffers(Packet);
        NdisDprFreePacket(Packet);

        if (pOrgPacket)
            NdisMSendComplete(
                pAdapt->MiniportHandle,
                pOrgPacket,
                Status
            );

        FreeFltPkt(pFltPkt);

    }
    else {

        NdisMSendComplete(
            pAdapt->MiniportHandle,
            Packet,
            Status
        );

    }

    InterlockedDecrement(&pAdapt->SendPending);
}

NDIS_STATUS
natpReceive(
    IN  NDIS_HANDLE	ProtocolBindingContext,
    IN  NDIS_HANDLE	MacReceiveContext,
    IN  PVOID		HeaderBuffer,
    IN  UINT		HeaderBufferSize,
    IN  PVOID		LookAheadBuffer,
    IN  UINT		LookAheadBufferSize,
    IN  UINT		PacketSize
)
{
    PFILTER_ADAPTER	pAdapt;
    PNDIS_PACKET Packet;
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    NDIS_STATUS PacketStatus;
    PNDIS_PACKET pNewPacket;
    ULONG nDataSize;
    FLT_PKT *pFltPkt;
    PNDIS_BUFFER pNewBuffer;

    pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    if ((!pAdapt->MiniportHandle) || (pAdapt->natmDeviceState > NdisDeviceStateD0)) {
        return NDIS_STATUS_FAILURE;
    }

    nDataSize = HeaderBufferSize + PacketSize;
    if (nDataSize > MAX_ETHER_SIZE) {
        return NDIS_STATUS_FAILURE;
    }

    Packet = NdisGetReceivedPacket(pAdapt->BindingHandle, MacReceiveContext);
    if (NULL == Packet)
        return NDIS_STATUS_NOT_ACCEPTED;

    pFltPkt = AllocateFltPacket();
    if (NULL == pFltPkt)
        return NDIS_STATUS_NOT_ACCEPTED;

    if (!natbParsePacket(Packet, pFltPkt)) {

        if (g_LogPktDrop) PrintFtlPkt("DROP ", pFltPkt, 0, FALSE);
        FreeFltPkt(pFltPkt);
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    //
    // Translate
    //
    TranslatePktIncoming(&pAdapt->ctrl, pFltPkt);

    //
    // Filter
    //
    if (!FilterPkt(&pAdapt->ctrl, pFltPkt, FALSE)) {

        if (g_LogPktDrop) PrintFtlPkt("DROP ", pFltPkt, 0, FALSE);
        FreeFltPkt(pFltPkt);
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    if (g_LogPktPass) PrintFtlPkt("PASS ", pFltPkt, 0, FALSE);

    if (NULL == pFltPkt->pBuf) {

        FreeFltPkt(pFltPkt);
        pFltPkt = NULL;

        NdisDprAllocatePacket(
            &Status,
            &pNewPacket,
            pAdapt->RcvPP1
        );

        if (Status != NDIS_STATUS_SUCCESS)
        {
            return NDIS_STATUS_NOT_ACCEPTED;
        }

        *((PVOID*)&pNewPacket->MiniportReserved) = NULL;

        pNewPacket->Private.Head = Packet->Private.Head;
        pNewPacket->Private.Tail = Packet->Private.Tail;

    }
    else {

        NdisDprAllocatePacket(
            &Status,
            &pNewPacket,
            pAdapt->RcvPP2
        );

        if (Status != NDIS_STATUS_SUCCESS)
            return NDIS_STATUS_NOT_ACCEPTED;

        *((PVOID*)&pNewPacket->MiniportReserved) = pFltPkt;

        NdisAllocateBuffer(
            &Status,
            &pNewBuffer,
            pAdapt->RcvBP,
            pFltPkt->pBuf,
            pFltPkt->uLen
        );

        if (Status != NDIS_STATUS_SUCCESS) {

            NdisReinitializePacket(pNewPacket);
            NdisFreePacket(pNewPacket);

            return NDIS_STATUS_NOT_ACCEPTED;
        }

        NdisChainBufferAtFront(pNewPacket, pNewBuffer);
    }

    NdisGetPacketFlags(pNewPacket) = NdisGetPacketFlags(Packet);

    NDIS_SET_PACKET_STATUS(pNewPacket, NDIS_STATUS_RESOURCES);

    NDIS_SET_ORIGINAL_PACKET(pNewPacket, NDIS_GET_ORIGINAL_PACKET(Packet));
    NDIS_SET_PACKET_HEADER_SIZE(pNewPacket, HeaderBufferSize);

    natpQueueReceivedPacket(pAdapt, pNewPacket, TRUE);

    natmReturnPacket(
        ProtocolBindingContext,
        pNewPacket
    );

    return Status;
}

VOID
natpReceiveComplete(
    IN NDIS_HANDLE	ProtocolBindingContext
)
{
    PFILTER_ADAPTER	pAdapt;
    pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    if (1 == InterlockedIncrement(&pAdapt->RcvCompleteProcessing))
        natpFlushReceiveQueue(pAdapt);

    if ((pAdapt->MiniportHandle != NULL)
        && (pAdapt->IndicateRcvComplete)) {
        switch (pAdapt->Medium) {
        case NdisMedium802_3:
            NdisMEthIndicateReceiveComplete(pAdapt->MiniportHandle);
            break;

        default:
            break;
        }
    }

    pAdapt->IndicateRcvComplete = FALSE;
    InterlockedDecrement(&pAdapt->RcvCompleteProcessing);
}

INT
natpReceivePacket(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_PACKET Packet
)
{
    PFILTER_ADAPTER pAdapt;
    NDIS_STATUS Status;
    PNDIS_BUFFER NdisBuffer;
    NDIS_STATUS PacketStatus;
    FLT_PKT *pFltPkt;

    pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    if (NULL == pAdapt->MiniportHandle || pAdapt->natmDeviceState > NdisDeviceStateD0)
        return 0;

    pFltPkt = AllocateFltPacket();
    if (NULL == pFltPkt)
        return 0;

    if (!natbParsePacket(Packet, pFltPkt)) {

        if (g_LogPktDrop) PrintFtlPkt("DROP ", pFltPkt, 0, FALSE);
        FreeFltPkt(pFltPkt);
        return 0;
    }

    //
    // Translate
    //
    TranslatePktIncoming(&pAdapt->ctrl, pFltPkt);

    //
    // Filter
    //
    if (!FilterPkt(&pAdapt->ctrl, pFltPkt, FALSE)) {

        if (g_LogPktDrop) PrintFtlPkt("DROP ", pFltPkt, 0, FALSE);
        FreeFltPkt(pFltPkt);
        return 0;
    }

    if (g_LogPktPass) PrintFtlPkt("PASS ", pFltPkt, 0, FALSE);

    if (NULL == pFltPkt->pBuf) {
        FreeFltPkt(pFltPkt);
        pFltPkt = NULL;
    }

    return natpReceivePacketPassThrough(ProtocolBindingContext, Packet, pFltPkt);
}

INT
natpReceivePacketPassThrough(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_PACKET Packet,
    IN FLT_PKT* pFltPkt
)
{
    PFILTER_ADAPTER pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;
    NDIS_STATUS Status;
    PNDIS_PACKET MyPacket;
    BOOLEAN Remaining;
    PNDIS_BUFFER		pNewBuffer;

    if (NULL == pAdapt->MiniportHandle || pAdapt->natmDeviceState > NdisDeviceStateD0)
        return 0;
    NdisIMGetCurrentPacketStack(Packet, &Remaining);
    if (NULL == pFltPkt && Remaining) {
        Status = NDIS_GET_PACKET_STATUS(Packet);
        NdisMIndicateReceivePacket(pAdapt->MiniportHandle, &Packet, 1);

        return Status != NDIS_STATUS_RESOURCES ? 1 : 0;
    }

    if (NULL == pFltPkt) {

        NdisDprAllocatePacket(
            &Status,
            &MyPacket,
            pAdapt->RcvPP1
        );

        if (Status != NDIS_STATUS_SUCCESS) {
            return 0;
        }

        *((PVOID*)&MyPacket->MiniportReserved) = Packet;

        MyPacket->Private.Head = Packet->Private.Head;
        MyPacket->Private.Tail = Packet->Private.Tail;

    }
    else {

        NdisDprAllocatePacket(
            &Status,
            &MyPacket,
            pAdapt->RcvPP2
        );

        if (Status != NDIS_STATUS_SUCCESS)
            return NDIS_STATUS_NOT_ACCEPTED;

        *((PVOID*)&MyPacket->MiniportReserved) = pFltPkt;

        NdisAllocateBuffer(
            &Status,
            &pNewBuffer,
            pAdapt->RcvBP,
            pFltPkt->pBuf,
            pFltPkt->uLen
        );

        if (Status != NDIS_STATUS_SUCCESS) {

            NdisReinitializePacket(MyPacket);
            NdisFreePacket(MyPacket);

            return 0;
        }

        NdisChainBufferAtFront(MyPacket, pNewBuffer);
    }
    NDIS_SET_ORIGINAL_PACKET(MyPacket, NDIS_GET_ORIGINAL_PACKET(Packet));
    NdisGetPacketFlags(MyPacket) = NdisGetPacketFlags(Packet);

    Status = NDIS_GET_PACKET_STATUS(Packet);

    NDIS_SET_PACKET_STATUS(MyPacket, Status);
    NDIS_SET_PACKET_HEADER_SIZE(MyPacket, NDIS_GET_PACKET_HEADER_SIZE(Packet));

    if (Status == NDIS_STATUS_RESOURCES) {

        natpQueueReceivedPacket(pAdapt, MyPacket, TRUE);
    }
    else {

        natpQueueReceivedPacket(pAdapt, MyPacket, FALSE);
    }

    if (Status == NDIS_STATUS_RESOURCES)
        NdisDprFreePacket(MyPacket);

    return Status != NDIS_STATUS_RESOURCES ? 1 : 0;
}

NDIS_STATUS
natpPNPHandler(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNET_PNP_EVENT pNetPnPEvent
)

{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    PFILTER_ADAPTER pAdapt = (PFILTER_ADAPTER)ProtocolBindingContext;

    switch (pNetPnPEvent->NetEvent) {
    case NetEventSetPower:
        Status = natpPnPNetEventSetPower(pAdapt, pNetPnPEvent);
        break;

    case NetEventReconfigure:
        Status = natpPnPNetEventReconfigure(pAdapt, pNetPnPEvent);
        break;

    default:
        Status = NDIS_STATUS_SUCCESS;
        break;
    }
    return Status;
}


NDIS_STATUS
natpPnPNetEventReconfigure(
    IN PFILTER_ADAPTER pAdapt,
    IN PNET_PNP_EVENT pNetPnPEvent
)
{
    if (pAdapt == NULL)
        NdisReEnumerateProtocolBindings(ProtHandle);

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
natpPnPNetEventSetPower(
    IN PFILTER_ADAPTER	pAdapt,
    IN PNET_PNP_EVENT	pNetPnPEvent
)
{
    PNDIS_DEVICE_POWER_STATE	pDeviceState = (PNDIS_DEVICE_POWER_STATE)(pNetPnPEvent->Buffer);
    NDIS_DEVICE_POWER_STATE		PrevDeviceState = pAdapt->natpDeviceState;
    NDIS_STATUS					Status;
    NDIS_STATUS					ReturnStatus;

    ReturnStatus = NDIS_STATUS_SUCCESS;

    NdisAcquireSpinLock(&pAdapt->Lock);
    pAdapt->natpDeviceState = *pDeviceState;

    if (pAdapt->natpDeviceState > NdisDeviceStateD0) {

        if (PrevDeviceState == NdisDeviceStateD0)
            pAdapt->StandingBy = TRUE;

        NdisReleaseSpinLock(&pAdapt->Lock);

        while (pAdapt->SendPending != 0)
            NdisMSleep(2);

        while (pAdapt->OutstandingRequests == TRUE)
            NdisMSleep(2);

        while (pAdapt->LocalOutstandingRequests == TRUE)
            NdisMSleep(2);

        NdisAcquireSpinLock(&pAdapt->Lock);
        if (pAdapt->QueuedRequest) {
            pAdapt->QueuedRequest = FALSE;
            NdisReleaseSpinLock(&pAdapt->Lock);
            natpRequestComplete(pAdapt, &pAdapt->IntReq.NdisRequest, NDIS_STATUS_FAILURE);
        }
        else {
            NdisReleaseSpinLock(&pAdapt->Lock);
        }

    }
    else {
        if (PrevDeviceState > NdisDeviceStateD0)
            pAdapt->StandingBy = FALSE;

        if (pAdapt->QueuedRequest == TRUE) {

            pAdapt->QueuedRequest = FALSE;

            pAdapt->OutstandingRequests = TRUE;
            NdisReleaseSpinLock(&pAdapt->Lock);

            NdisRequest(
                &Status,
                pAdapt->BindingHandle,
                &pAdapt->IntReq.NdisRequest
            );

            if (Status != NDIS_STATUS_PENDING) {
                natpRequestComplete(
                    pAdapt,
                    &pAdapt->IntReq.NdisRequest,
                    Status
                );

            }

        }
        else {
            NdisReleaseSpinLock(&pAdapt->Lock);
        }
    }

    return ReturnStatus;
}


VOID
natpQueueReceivedPacket(
    IN PFILTER_ADAPTER pAdapt,
    IN PNDIS_PACKET Packet,
    IN BOOLEAN DoIndicate
)
{
    PNDIS_PACKET PacketArray[MAX_RCV_PKT_ARR_SZ];
    ULONG NumberOfPackets = 0, i;

    NdisDprAcquireSpinLock(&pAdapt->Lock);
    ASSERT(pAdapt->ReceivedPacketCount < MAX_RCV_PKT_ARR_SZ);

    pAdapt->ReceivedPackets[pAdapt->ReceivedPacketCount] = Packet;
    pAdapt->ReceivedPacketCount++;

    if ((pAdapt->ReceivedPacketCount == MAX_RCV_PKT_ARR_SZ) || DoIndicate) {

        NdisMoveMemory(PacketArray,
            pAdapt->ReceivedPackets,
            pAdapt->ReceivedPacketCount * sizeof(PNDIS_PACKET));

        NumberOfPackets = pAdapt->ReceivedPacketCount;

        pAdapt->ReceivedPacketCount = 0;

        NdisDprReleaseSpinLock(&pAdapt->Lock);

        if ((pAdapt->MiniportHandle != NULL) && (pAdapt->natmDeviceState == NdisDeviceStateD0)) {
            NdisMIndicateReceivePacket(pAdapt->MiniportHandle, PacketArray, NumberOfPackets);

        }
        else {

            if (DoIndicate)
                NumberOfPackets -= 1;

            for (i = 0; i < NumberOfPackets; i++)
                natmReturnPacket(pAdapt, PacketArray[i]);

        }

    }
    else
        NdisDprReleaseSpinLock(&pAdapt->Lock);

}

VOID
natpFlushReceiveQueue(
    IN PFILTER_ADAPTER pAdapt
)
{
    PNDIS_PACKET PacketArray[MAX_RCV_PKT_ARR_SZ];
    ULONG NumberOfPackets = 0, i;

    __try {

        NdisDprAcquireSpinLock(&pAdapt->Lock);

        if (pAdapt->ReceivedPacketCount > 0) {

            NdisMoveMemory(PacketArray,
                pAdapt->ReceivedPackets,
                pAdapt->ReceivedPacketCount * sizeof(PNDIS_PACKET));

            NumberOfPackets = pAdapt->ReceivedPacketCount;

            pAdapt->ReceivedPacketCount = 0;

            NdisDprReleaseSpinLock(&pAdapt->Lock);

            if ((pAdapt->MiniportHandle) && (pAdapt->natmDeviceState == NdisDeviceStateD0)) {

                NdisMIndicateReceivePacket(pAdapt->MiniportHandle,
                    PacketArray,
                    NumberOfPackets);
                __leave;
            }

            for (i = 0; i < NumberOfPackets; i++)
                natmReturnPacket(pAdapt, PacketArray[i]);

            __leave;
        }

        NdisDprReleaseSpinLock(&pAdapt->Lock);

    }
    __finally {}

}

VOID
MakeCurrentAddressQueryComplete(
    IN PFILTER_ADAPTER pAdapter,
    PINTERNAL_REQUEST	pInternalRequest,
    NDIS_STATUS			Status
)
{
    NDIS_STATUS      ndisStatus;

    if (pInternalRequest->nRequestStatus != NDIS_STATUS_SUCCESS)
        pAdapter->ctrl.MacAddr.Val = 0;
}

VOID
StartQueryInfo(
    IN PFILTER_ADAPTER pAdapter
)
{
    NTSTATUS             nNtStatus;
    PINTERNAL_REQUEST    pIntReq;

    pIntReq = &pAdapter->IntReq;

    RtlZeroMemory(pIntReq, sizeof(*pIntReq));

    pIntReq->NdisRequest.RequestType = NdisRequestQueryInformation;
    pIntReq->NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_802_3_CURRENT_ADDRESS;
    pIntReq->NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = pAdapter->ctrl.MacAddr.Arr;
    pIntReq->NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof(pAdapter->ctrl.MacAddr.Arr);

    nNtStatus = NDIS_STATUS_FAILURE;
    pIntReq->nRequestStatus = NDIS_STATUS_PENDING;

    pIntReq->bLocalRequest = TRUE;
    pIntReq->pLocalCompletionFunc = MakeCurrentAddressQueryComplete;
    pAdapter->LocalOutstandingRequests = TRUE;

    NdisRequest(
        &nNtStatus,
        pAdapter->BindingHandle,
        &pIntReq->NdisRequest
    );

    if (nNtStatus != NDIS_STATUS_PENDING) {
        natpRequestComplete(
            (NDIS_HANDLE)pAdapter,
            &pIntReq->NdisRequest,
            nNtStatus
        );
    }

}