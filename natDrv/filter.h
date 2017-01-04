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

typedef struct _INTERNAL_REQUEST {

    BOOLEAN        bLocalRequest;
    NDIS_STATUS    nRequestStatus;
    NDIS_REQUEST   NdisRequest;
    VOID(*pLocalCompletionFunc)();

}INTERNAL_REQUEST, *PINTERNAL_REQUEST;

typedef struct _FILTER_ADAPTER
{
    FILTER_COMMON_CONTROL_BLOCK ctrl;

    NDIS_HANDLE		BindingHandle;
    NDIS_HANDLE		MiniportHandle;

    LONG			SendPending;

    NDIS_HANDLE		SndPP1;
    NDIS_HANDLE		SndPP2;
    NDIS_HANDLE		SndBP;
    NDIS_HANDLE		RcvPP1;
    NDIS_HANDLE		RcvPP2;
    NDIS_HANDLE		RcvBP;


    LONG			StandingBy;
    LONG			UnbindingInProcess;
    NDIS_SPIN_LOCK		Lock;

    NDIS_DEVICE_POWER_STATE	natmDeviceState;
    NDIS_DEVICE_POWER_STATE	natpDeviceState;

    NDIS_STRING		DeviceName;
    NDIS_STRING		RootDeviceName;
    NDIS_EVENT		MiniportInitEvent;

    LONG			MiniportInitPending;
    NDIS_STATUS		LastIndicatedStatus;
    NDIS_STATUS		LatestUnIndicateStatus;

    ULONG			ReceivedPacketCount;
    PNDIS_PACKET		ReceivedPackets[MAX_RCV_PKT_ARR_SZ];

    ULONG			Flags;
    NDIS_STATUS		Status;
    NDIS_EVENT		Event;
    NDIS_MEDIUM		Medium;

    INTERNAL_REQUEST	IntReq;
    LONG			QueuedRequest;
    LONG			OutstandingRequests;
    ULONG			LocalOutstandingRequests;

    PULONG			BytesNeeded;
    PULONG			BytesReadOrWritten;
    LONG			IndicateRcvComplete;
    LONG			RcvCompleteProcessing;

}FILTER_ADAPTER, *PFILTER_ADAPTER;

NTSTATUS
natpDispatch(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP	Irp
);

NDIS_STATUS
natpRegisterDevice(
    VOID
);

NDIS_STATUS
natpDeregisterDevice(
    VOID
);

VOID
natpUnloadProtocol(
    VOID
);

void
natpOpenAdapterComplete(
    IN NDIS_HANDLE	ProtocolBindingContext,
    IN NDIS_STATUS	Status,
    IN NDIS_STATUS	OpenErrorStatus
);

VOID
natpCloseAdapterComplete(
    IN NDIS_HANDLE	ProtocolBindingContext,
    IN NDIS_STATUS	Status
);

void
natpResetComplete(
    IN NDIS_HANDLE	ProtocolBindingContext,
    IN NDIS_STATUS	Status
);

void
natpRequestComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_REQUEST NdisRequest,
    IN NDIS_STATUS Status
);

void
natpStatus(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS GeneralStatus,
    IN PVOID StatusBuffer,
    IN UINT StatusBufferSize
);

void
natpStatusComplete(
    IN NDIS_HANDLE ProtocolBindingContext
);

void
natpSendComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_PACKET Packet,
    IN NDIS_STATUS Status
);

void
natpTransferDataComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_PACKET Packet,
    IN NDIS_STATUS Status,
    IN UINT BytesTransferred
);

NDIS_STATUS
natpReceive(
    IN NDIS_HANDLE	ProtocolBindingContext,
    IN NDIS_HANDLE	MacReceiveContext,
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize,
    IN PVOID LookAheadBuffer,
    IN UINT LookaheadBufferSize,
    IN UINT PacketSize
);

NDIS_STATUS
natpReceivePassThrough(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_PACKET Packet,
    IN ULONG HeaderBufferSize
);

void
natpReceiveComplete(
    IN NDIS_HANDLE ProtocolBindingContext
);

int
natpReceivePacket(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_PACKET Packet
);

void
natpBindAdapter(
    OUT PNDIS_STATUS Status,
    IN  NDIS_HANDLE BindContext,
    IN  PNDIS_STRING DeviceName,
    IN  PVOID SystemSpecific1,
    IN  PVOID SystemSpecific2
);

void
natpUnbindAdapter(
    OUT PNDIS_STATUS Status,
    IN  NDIS_HANDLE ProtocolBindingContext,
    IN  NDIS_HANDLE UnbindContext
);

void
natpUnload(
    IN PDRIVER_OBJECT DriverObject
);

NDIS_STATUS
natpPNPHandler(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNET_PNP_EVENT pNetPnPEvent
);

NDIS_STATUS
natpPnPNetEventReconfigure(
    IN PFILTER_ADAPTER pAdapt,
    IN PNET_PNP_EVENT pNetPnPEvent
);

NDIS_STATUS
natpPnPNetEventSetPower(
    IN PFILTER_ADAPTER pAdapt,
    IN PNET_PNP_EVENT pNetPnPEvent
);

NDIS_STATUS
natpDeviceIoControlDispatch(
    IN ULONG ControlCode,
    IN PUCHAR InputBuffer,
    IN ULONG InputBufferLength,
    IN PUCHAR OutputBuffer,
    IN ULONG OutputBufferLength,
    IN OUT PULONG ReturnedSize
);

NDIS_STATUS
natmInitialize(
    OUT PNDIS_STATUS OpenErrorStatus,
    OUT PUINT SelectedMediumIndex,
    IN PNDIS_MEDIUM MediumArray,
    IN UINT MediumArraySize,
    IN NDIS_HANDLE MiniportAdapterHandle,
    IN NDIS_HANDLE WrapperConfigurationContext
);

VOID
natmSendPackets(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PPNDIS_PACKET PacketArray,
    IN UINT NumberOfPackets
);

NDIS_STATUS
natmQueryInformation(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesWritten,
    OUT PULONG BytesNeeded
);

NDIS_STATUS
natmSetInformation(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesRead,
    OUT PULONG BytesNeeded
);

VOID
natmReturnPacket(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PNDIS_PACKET Packet
);

NDIS_STATUS
natmTransferData(
    OUT PNDIS_PACKET Packet,
    OUT PUINT BytesTransferred,
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_HANDLE MiniportReceiveContext,
    IN UINT ByteOffset,
    IN UINT BytesToTransfer
);

VOID
natmHalt(
    IN NDIS_HANDLE MiniportAdapterContext
);


VOID
natmQueryPNPCapabilities(
    OUT PFILTER_ADAPTER MiniportProtocolContext,
    OUT PNDIS_STATUS Status
);

VOID
natmFreeAllPacketPools(
    IN PFILTER_ADAPTER pAdapt
);

VOID
natmProcessSetPowerOid(
    IN OUT PNDIS_STATUS pNdisStatus,
    IN PFILTER_ADAPTER pAdapt,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesRead,
    OUT PULONG BytesNeeded
);

VOID
natmCancelSendPackets(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PVOID CancelId
);

VOID
natmDevicePnPEvent(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_DEVICE_PNP_EVENT DevicePnPEvent,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength
);

VOID
natmAdapterShutdown(
    IN NDIS_HANDLE MiniportAdapterContext
);

VOID
natmFreeBuffers(
    IN OUT PNDIS_PACKET Packet
);


extern NDIS_HANDLE ProtHandle, DriverHandle;
extern NDIS_MEDIUM MediumArray[4];
extern UNICODE_STRING g_RegistryPath;

#define IsIMDeviceStateOn(_pP)	((_pP)->natmDeviceState == NdisDeviceStateD0 && (_pP)->natpDeviceState == NdisDeviceStateD0 ) 
