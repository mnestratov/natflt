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

typedef enum _DEVICE_STATE
{
	PS_DEVICE_STATE_READY = 0,
	PS_DEVICE_STATE_CREATING,
	PS_DEVICE_STATE_DELETING
} DEVICE_STATE,*PDEVICE_STATE;

NDIS_HANDLE	ProtHandle = NULL;
NDIS_HANDLE	DriverHandle = NULL;
NDIS_MEDIUM	MediumArray[4] = {
	NdisMedium802_3,
};

WCHAR g_RegistryPathBuf[255] = {0};
UNICODE_STRING g_RegistryPath = {0, sizeof(g_RegistryPathBuf), g_RegistryPathBuf};

NDIS_HANDLE NdisWrapperHandle;
NDIS_HANDLE NdisDeviceHandle = NULL;
PDEVICE_OBJECT ControlDeviceObject = NULL;
DEVICE_STATE ControlDeviceState = PS_DEVICE_STATE_READY;
LONG MiniportCount = 0;

NTSTATUS
	DriverEntry(
		IN PDRIVER_OBJECT DriverObject,
		IN PUNICODE_STRING RegistryPath
		);

NTSTATUS
	natpDispatch(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp
		);

#pragma NDIS_INIT_FUNCTION(DriverEntry)

NTSTATUS
	DriverEntry(
		IN PDRIVER_OBJECT DriverObject,
		IN PUNICODE_STRING RegistryPath
		)
{
	NDIS_STATUS Status;
	NDIS_PROTOCOL_CHARACTERISTICS PChars;
	NDIS_MINIPORT_CHARACTERISTICS MChars;
	NDIS_STRING Name;
	BOOLEAN bLayeredMiniportRegistered=FALSE;
	BOOLEAN bProtocolRegistered=FALSE;

	Status = NDIS_STATUS_SUCCESS;
	NdisAllocateSpinLock(&g_AdapterListLock);
	InitializeListHead(&g_AdapterListHead);

	RtlCopyUnicodeString(&g_RegistryPath, RegistryPath );
	
	NdisMInitializeWrapper(&NdisWrapperHandle, DriverObject, RegistryPath, NULL);

	InitPacketLookaside();
	natInitTraced();
	
	natInitFwSession();
	natReadRegValues(RegistryPath);

	__try{
		
		NdisZeroMemory(&MChars, sizeof(NDIS_MINIPORT_CHARACTERISTICS));

		MChars.MajorNdisVersion = 5;
		MChars.MinorNdisVersion = 1;

		MChars.InitializeHandler = natmInitialize;
		MChars.QueryInformationHandler = natmQueryInformation;
		MChars.SetInformationHandler = natmSetInformation;
		MChars.ResetHandler = NULL;
		MChars.TransferDataHandler = natmTransferData;
		MChars.HaltHandler = natmHalt;

		MChars.CancelSendPacketsHandler = natmCancelSendPackets;
		MChars.PnPEventNotifyHandler = natmDevicePnPEvent;
		MChars.AdapterShutdownHandler = natmAdapterShutdown;

		MChars.CheckForHangHandler = NULL;
		MChars.ReturnPacketHandler = natmReturnPacket;

		MChars.SendHandler = NULL;
		MChars.SendPacketsHandler = natmSendPackets;

		Status = 
			NdisIMRegisterLayeredMiniport(
				NdisWrapperHandle,
				&MChars,
				sizeof(MChars),
				&DriverHandle
				);

		if (Status != NDIS_STATUS_SUCCESS)
			__leave;

		bLayeredMiniportRegistered = TRUE;

		NdisMRegisterUnloadHandler(NdisWrapperHandle, natpUnload);

		NdisZeroMemory(&PChars, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
		PChars.MajorNdisVersion = 5;
		PChars.MinorNdisVersion = 1;

		NdisInitUnicodeString(&Name, L"natdrv");
		PChars.Name = Name;
		PChars.OpenAdapterCompleteHandler = natpOpenAdapterComplete;
		PChars.CloseAdapterCompleteHandler = natpCloseAdapterComplete;
		PChars.SendCompleteHandler = natpSendComplete;
		PChars.TransferDataCompleteHandler = NULL;

		PChars.ResetCompleteHandler = natpResetComplete;
		PChars.RequestCompleteHandler = natpRequestComplete;
		PChars.ReceiveHandler = natpReceive;
		PChars.ReceiveCompleteHandler = natpReceiveComplete;
		PChars.StatusHandler = natpStatus;
		PChars.StatusCompleteHandler = natpStatusComplete;
		PChars.BindAdapterHandler = natpBindAdapter;
		PChars.UnbindAdapterHandler = natpUnbindAdapter;
		PChars.UnloadHandler = natpUnloadProtocol;

		PChars.ReceivePacketHandler = natpReceivePacket;
		PChars.PnPEventHandler= natpPNPHandler;

		NdisRegisterProtocol(
			&Status,
			&ProtHandle,
			&PChars,
			sizeof(NDIS_PROTOCOL_CHARACTERISTICS)
			);

		if (Status != NDIS_STATUS_SUCCESS)
			__leave;

		bProtocolRegistered = TRUE;

		NdisIMAssociateMiniport(DriverHandle, ProtHandle);

	}
	__finally{
	}

	if (Status != NDIS_STATUS_SUCCESS){

		ReleasePacketLookaside();

		if (bProtocolRegistered){
			NdisDeregisterProtocol(&Status, ProtHandle);
			bProtocolRegistered = FALSE;
		}

		if (bLayeredMiniportRegistered){
			NdisIMDeregisterLayeredMiniport(DriverHandle);
			bLayeredMiniportRegistered = FALSE;
		}

		NdisTerminateWrapper(NdisWrapperHandle, NULL);
	}

	return Status;
}

NDIS_STATUS
	natpRegisterDevice(
		VOID
		)
{
	NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
	UNICODE_STRING DeviceName;
	UNICODE_STRING DeviceLinkUnicodeString;
	PDRIVER_DISPATCH DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];

	NdisAcquireSpinLock(&g_AdapterListLock);

	++MiniportCount;

	if (1 == MiniportCount){

		ASSERT(ControlDeviceState != PS_DEVICE_STATE_CREATING);

		while (ControlDeviceState != PS_DEVICE_STATE_READY){
			NdisReleaseSpinLock(&g_AdapterListLock);
			NdisMSleep(1);
			NdisAcquireSpinLock(&g_AdapterListLock);
		}

		ControlDeviceState = PS_DEVICE_STATE_CREATING;

		NdisReleaseSpinLock(&g_AdapterListLock);

		NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));

		DispatchTable[IRP_MJ_CREATE] = natpDispatch;
		DispatchTable[IRP_MJ_CLEANUP] = natpDispatch;
		DispatchTable[IRP_MJ_CLOSE] = natpDispatch;
		DispatchTable[IRP_MJ_DEVICE_CONTROL] = natpDispatch;

		NdisInitUnicodeString(&DeviceName, FILTER_NT_DEVICE_NAME);
		NdisInitUnicodeString(&DeviceLinkUnicodeString, FILTER_DOSDEVICE_NAME);

		Status = 
			NdisMRegisterDevice(
				NdisWrapperHandle, 
				&DeviceName,
				&DeviceLinkUnicodeString,
				&DispatchTable[0],
				&ControlDeviceObject,
				&NdisDeviceHandle
				);

		NdisAcquireSpinLock(&g_AdapterListLock);

		ControlDeviceState = PS_DEVICE_STATE_READY;
	}

	NdisReleaseSpinLock(&g_AdapterListLock);

	return Status;
}



NDIS_STATUS
	natpDeregisterDevice(
		VOID
		)
{
	NDIS_STATUS Status = NDIS_STATUS_SUCCESS;

	NdisAcquireSpinLock(&g_AdapterListLock);

	ASSERT(MiniportCount > 0);

	--MiniportCount;

	if (0 == MiniportCount){

		ASSERT(ControlDeviceState == PS_DEVICE_STATE_READY);

		ControlDeviceState = PS_DEVICE_STATE_DELETING;

		NdisReleaseSpinLock(&g_AdapterListLock);

		if (NdisDeviceHandle != NULL){

			Status = 
				NdisMDeregisterDevice(
					NdisDeviceHandle
					);
			NdisDeviceHandle = NULL;
		}

		NdisAcquireSpinLock(&g_AdapterListLock);
		ControlDeviceState = PS_DEVICE_STATE_READY;
	}

	NdisReleaseSpinLock(&g_AdapterListLock);

	return Status;

}

void
	natpUnload(
		IN PDRIVER_OBJECT DriverObject
		)
{
	UNREFERENCED_PARAMETER(DriverObject);

	natDeinitFwSession();
	natReleaseTracedAll();

	natpUnloadProtocol();
	NdisIMDeregisterLayeredMiniport(DriverHandle);

	NdisFreeSpinLock(&g_AdapterListLock);

	ReleasePacketLookaside();
}

