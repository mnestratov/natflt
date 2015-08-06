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

NDIS_STATUS
	natmInitialize(
		OUT PNDIS_STATUS OpenErrorStatus,
		OUT PUINT SelectedMediumIndex,
		IN  PNDIS_MEDIUM MediumArray,
		IN  UINT MediumArraySize,
		IN  NDIS_HANDLE MiniportAdapterHandle,
		IN  NDIS_HANDLE WrapperConfigurationContext
		)
{
	UINT i;
	PFILTER_ADAPTER	pAdapt;
	NDIS_STATUS Status = NDIS_STATUS_FAILURE;
	NDIS_MEDIUM Medium;

	UNREFERENCED_PARAMETER(WrapperConfigurationContext);

	__try{
		
		pAdapt = NdisIMGetDeviceContext(MiniportAdapterHandle);
		pAdapt->MiniportHandle = MiniportAdapterHandle;

		Medium = pAdapt->Medium;

		if (Medium == NdisMediumWan)
			Medium = NdisMedium802_3;

		for (i = 0; i < MediumArraySize; i++){
		
			if (MediumArray[i] == Medium){
				*SelectedMediumIndex = i;
				break;
			}
		}

		if (i == MediumArraySize){

			Status = NDIS_STATUS_UNSUPPORTED_MEDIA;
			__leave;
		}

		NdisMSetAttributesEx(
			MiniportAdapterHandle,
			pAdapt,
			0,
			NDIS_ATTRIBUTE_IGNORE_PACKET_TIMEOUT    |
			NDIS_ATTRIBUTE_IGNORE_REQUEST_TIMEOUT|
			NDIS_ATTRIBUTE_INTERMEDIATE_DRIVER |
			NDIS_ATTRIBUTE_DESERIALIZE |
			NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND,
			0);

		pAdapt->LastIndicatedStatus = NDIS_STATUS_MEDIA_CONNECT;
		pAdapt->natmDeviceState = NdisDeviceStateD0;
		pAdapt->natpDeviceState = NdisDeviceStateD0;

		NdisAcquireSpinLock(&g_AdapterListLock);
		InsertTailList(&g_AdapterListHead, &pAdapt->ctrl.ListEntry);
		NdisReleaseSpinLock(&g_AdapterListLock);

		natpRegisterDevice();
		Status = NDIS_STATUS_SUCCESS;

	}__finally{

	}

	ASSERT(pAdapt->MiniportInitPending == TRUE);
	pAdapt->MiniportInitPending = FALSE;
	NdisSetEvent(&pAdapt->MiniportInitEvent);

	*OpenErrorStatus = Status;

	return Status;
}

NDIS_STATUS
	natmSendPassThrough(
		IN NDIS_HANDLE  MiniportAdapterContext,
		IN PNDIS_PACKET Packet,
		IN FLT_PKT* pFltPkt
		)
{
	PFILTER_ADAPTER pAdapt;
	NDIS_STATUS Status;
	PVOID MediaSpecificInfo = NULL;
	ULONG MediaSpecificInfoSize = 0;
	PNDIS_PACKET_STACK pStack;
	BOOLEAN StackRoomLeft;
	PNDIS_PACKET pNewPacket;
	PNDIS_BUFFER pNewBuffer = NULL;

	pAdapt = (PFILTER_ADAPTER)MiniportAdapterContext;

	NdisAcquireSpinLock(&pAdapt->Lock);
	if (pAdapt->natpDeviceState > NdisDeviceStateD0 || 
		pAdapt->natmDeviceState > NdisDeviceStateD0)
	{
		NdisReleaseSpinLock(&pAdapt->Lock);
		return NDIS_STATUS_FAILURE;
	}
	NdisReleaseSpinLock(&pAdapt->Lock);
    
	pStack = NdisIMGetCurrentPacketStack(Packet, &StackRoomLeft);
	if (NULL == pFltPkt && StackRoomLeft && pStack){

		ASSERT(pStack);
		pStack->IMReserved[0] = (ULONG_PTR)NULL;

		InterlockedIncrement(&pAdapt->SendPending);

		NdisSendPackets(
				pAdapt->BindingHandle,
				&Packet,
				1
			);

		return NDIS_STATUS_PENDING;
	}

	if(NULL == pFltPkt){

		NdisAllocatePacket(
			&Status,
			&pNewPacket,
			pAdapt->SndPP1
			);

		if (Status != NDIS_STATUS_SUCCESS){

			NdisMSendComplete(
				pAdapt->MiniportHandle,
				Packet,
				Status
				);
			return Status;
		}

		*((PVOID*)pNewPacket->ProtocolReserved) = Packet;

		pNewPacket->Private.Head = Packet->Private.Head;
		pNewPacket->Private.Tail = Packet->Private.Tail;

	}else{

		ASSERT(pFltPkt->pBuf);

		NdisAllocatePacket(
			&Status,
			&pNewPacket,
			pAdapt->SndPP2
			);

		if (Status != NDIS_STATUS_SUCCESS){

			NdisMSendComplete(
				pAdapt->MiniportHandle,
				Packet,
				Status
				);
			return Status;
		}

		*((PVOID*)pNewPacket->ProtocolReserved) = pFltPkt;

		NdisAllocateBuffer(
			&Status,
			&pNewBuffer,
			pAdapt->SndBP,
			pFltPkt->pBuf,
			pFltPkt->uLen
			);

		if ( Status != NDIS_STATUS_SUCCESS ){

			NdisReinitializePacket (pNewPacket);
			NdisFreePacket (pNewPacket);

			NdisMSendComplete(
				pAdapt->MiniportHandle,
				Packet,
				Status
				);
			return Status;
		}

		NdisChainBufferAtFront(pNewPacket, pNewBuffer );

	}        

	NdisSetPacketFlags(pNewPacket,NdisGetPacketFlags(Packet));
		
	NdisMoveMemory(NDIS_OOB_DATA_FROM_PACKET(pNewPacket),
                   NDIS_OOB_DATA_FROM_PACKET(Packet),
                   sizeof(NDIS_PACKET_OOB_DATA));

	NdisIMCopySendPerPacketInfo(pNewPacket, Packet);
  
	NDIS_GET_PACKET_MEDIA_SPECIFIC_INFO(Packet,
                                        &MediaSpecificInfo,
                                        &MediaSpecificInfoSize);

	if (MediaSpecificInfo || MediaSpecificInfoSize){

		NDIS_SET_PACKET_MEDIA_SPECIFIC_INFO(pNewPacket,
                                            MediaSpecificInfo,
                                            MediaSpecificInfoSize);
	}

	InterlockedIncrement(&pAdapt->SendPending);
	NdisSendPackets(
			pAdapt->BindingHandle,
			&pNewPacket,
			1
			);

	Status = NDIS_STATUS_PENDING;
	return Status;
}

void
	natmSendPackets(
		IN NDIS_HANDLE MiniportAdapterContext,
		IN PPNDIS_PACKET PacketArray,
		IN UINT NumberOfPackets
		)
{
	PFILTER_ADAPTER	pAdapt;
	NDIS_STATUS Status;
	UINT i;
	PVOID MediaSpecificInfo = NULL;
	UINT MediaSpecificInfoSize = 0;
	FLT_PKT *pFltPkt;

	pAdapt = (PFILTER_ADAPTER)MiniportAdapterContext;

	for (i = 0; i < NumberOfPackets; i++){

		PNDIS_PACKET    Packet;

		Packet = PacketArray[i];

		if (pAdapt->natmDeviceState > NdisDeviceStateD0){

				NdisMSendComplete(
					pAdapt->MiniportHandle,
					Packet,
					NDIS_STATUS_FAILURE
					);
				continue;
		}

		pFltPkt = AllocateFltPacket();
		if(NULL == pFltPkt){

			NdisMSendComplete(
				pAdapt->MiniportHandle,
				Packet,
				NDIS_STATUS_FAILURE
				);
			continue;
		}

		if(!natbParsePacket(Packet, pFltPkt)){

			if(g_LogPktDrop) PrintFtlPkt("DROP ", pFltPkt, 0, TRUE);

			FreeFltPkt(pFltPkt);
			NdisMSendComplete(
				pAdapt->MiniportHandle,
				Packet,
				NDIS_STATUS_FAILURE
				);
			continue;
		}

		//
		// Filter
		//
		if(!FilterPkt(&pAdapt->ctrl, pFltPkt, TRUE)){

			if(g_LogPktDrop) PrintFtlPkt("DROP ", pFltPkt, 0, TRUE);

			FreeFltPkt(pFltPkt);
			NdisMSendComplete(
				pAdapt->MiniportHandle,
				Packet,
				NDIS_STATUS_FAILURE
				);
			continue;
		}

		//
		// Translate
		//
		TranslatePktOutgoing(&pAdapt->ctrl, pFltPkt);

		if(g_LogPktPass) PrintFtlPkt("PASS ", pFltPkt, 0, TRUE);

		if(NULL == pFltPkt->pBuf){
			FreeFltPkt(pFltPkt);
			pFltPkt = NULL;
		}

	    natmSendPassThrough( MiniportAdapterContext, Packet, pFltPkt );

	} // for (i = 0; i < NumberOfPackets; i++){

}

NDIS_STATUS
	natmQueryInformation(
		IN NDIS_HANDLE MiniportAdapterContext,
		IN NDIS_OID Oid,
		IN PVOID InformationBuffer,
		IN ULONG InformationBufferLength,
		OUT PULONG BytesWritten,
		OUT PULONG BytesNeeded
		)
{
	PFILTER_ADAPTER	pAdapt;
	NDIS_STATUS Status = NDIS_STATUS_FAILURE;

	pAdapt = (PFILTER_ADAPTER)MiniportAdapterContext;

	if (Oid == OID_PNP_QUERY_POWER){
		Status = NDIS_STATUS_SUCCESS;
		goto finish;
	}

	if (Oid == OID_GEN_SUPPORTED_GUIDS){
		Status = NDIS_STATUS_NOT_SUPPORTED;
		goto finish;
	}

	if (Oid == OID_TCP_TASK_OFFLOAD){
		Status = NDIS_STATUS_NOT_SUPPORTED;
		goto finish;
	}

	NdisAcquireSpinLock(&pAdapt->Lock);
	if (pAdapt->UnbindingInProcess == TRUE){
		NdisReleaseSpinLock(&pAdapt->Lock);
		Status = NDIS_STATUS_FAILURE;
		goto finish;
	}
	NdisReleaseSpinLock(&pAdapt->Lock);

	if (pAdapt->natmDeviceState > NdisDeviceStateD0){
		Status = NDIS_STATUS_FAILURE;
		goto finish;
	}

	pAdapt->IntReq.bLocalRequest = FALSE;
	pAdapt->IntReq.nRequestStatus = NDIS_STATUS_PENDING;

	pAdapt->IntReq.NdisRequest.RequestType = NdisRequestQueryInformation;
	pAdapt->IntReq.NdisRequest.DATA.QUERY_INFORMATION.Oid = Oid;
	pAdapt->IntReq.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = InformationBuffer;
	pAdapt->IntReq.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = InformationBufferLength;
	pAdapt->BytesNeeded = BytesNeeded;
	pAdapt->BytesReadOrWritten = BytesWritten;

	NdisAcquireSpinLock(&pAdapt->Lock);

	if (pAdapt->UnbindingInProcess == TRUE){
		NdisReleaseSpinLock(&pAdapt->Lock);
		Status = NDIS_STATUS_FAILURE;
		goto finish;
	}

	if ((pAdapt->natpDeviceState > NdisDeviceStateD0) 
		&& (pAdapt->StandingBy == FALSE)){
		pAdapt->QueuedRequest = TRUE;
		NdisReleaseSpinLock(&pAdapt->Lock);
		Status = NDIS_STATUS_PENDING;
		goto finish;
	}

	if (pAdapt->StandingBy == TRUE){
		NdisReleaseSpinLock(&pAdapt->Lock);
		Status = NDIS_STATUS_FAILURE;
		goto finish;
	}
	pAdapt->OutstandingRequests = TRUE;

	NdisReleaseSpinLock(&pAdapt->Lock);

	NdisRequest(
		&Status,
		pAdapt->BindingHandle,
		&pAdapt->IntReq.NdisRequest
		);

	if (Status != NDIS_STATUS_PENDING){
		natpRequestComplete(pAdapt, &pAdapt->IntReq.NdisRequest, Status);
		Status = NDIS_STATUS_PENDING;
	}

finish:

	return Status;
}

void
	natmQueryPNPCapabilities(
		IN OUT PFILTER_ADAPTER	pAdapt,
		OUT PNDIS_STATUS	pStatus
		)
{
	PNDIS_PNP_CAPABILITIES			pPNPCapabilities;
	PNDIS_PM_WAKE_UP_CAPABILITIES	pPMstruct;

	if (pAdapt->IntReq.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength >= sizeof(NDIS_PNP_CAPABILITIES)){
		pPNPCapabilities = (PNDIS_PNP_CAPABILITIES)(pAdapt->IntReq.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer);

		pPMstruct= & pPNPCapabilities->WakeUpCapabilities;
		pPMstruct->MinMagicPacketWakeUp = NdisDeviceStateUnspecified;
		pPMstruct->MinPatternWakeUp = NdisDeviceStateUnspecified;
		pPMstruct->MinLinkChangeWakeUp = NdisDeviceStateUnspecified;
		*pAdapt->BytesReadOrWritten = sizeof(NDIS_PNP_CAPABILITIES);
		*pAdapt->BytesNeeded = 0;


		pAdapt->natmDeviceState = NdisDeviceStateD0;
		pAdapt->natpDeviceState = NdisDeviceStateD0;

		*pStatus = NDIS_STATUS_SUCCESS;
	}else{
		*pAdapt->BytesNeeded= sizeof(NDIS_PNP_CAPABILITIES);
		*pStatus = NDIS_STATUS_RESOURCES;
	}
}


NDIS_STATUS
	natmSetInformation(
		IN NDIS_HANDLE MiniportAdapterContext,
		IN NDIS_OID Oid,
		IN PVOID InformationBuffer,
		IN ULONG InformationBufferLength,
		OUT PULONG BytesRead,
		OUT PULONG BytesNeeded
		)
{
	PFILTER_ADAPTER	pAdapt;
	NDIS_STATUS Status;

	pAdapt = (PFILTER_ADAPTER)MiniportAdapterContext;
	Status = NDIS_STATUS_FAILURE;

	if (Oid == OID_PNP_SET_POWER){
		natmProcessSetPowerOid(
			&Status,
			pAdapt,
			InformationBuffer,
			InformationBufferLength,
			BytesRead,
			BytesNeeded
			);
		goto finish;
	}

	NdisAcquireSpinLock(&pAdapt->Lock);
	if (pAdapt->UnbindingInProcess == TRUE){
		NdisReleaseSpinLock(&pAdapt->Lock);
		Status = NDIS_STATUS_FAILURE;
		goto finish;
	}
	NdisReleaseSpinLock(&pAdapt->Lock);

	if (pAdapt->natmDeviceState > NdisDeviceStateD0){
		Status = NDIS_STATUS_FAILURE;
		goto finish;
	}

	pAdapt->IntReq.bLocalRequest = FALSE;
	pAdapt->IntReq.nRequestStatus = NDIS_STATUS_PENDING;		

	pAdapt->IntReq.NdisRequest.RequestType = NdisRequestSetInformation;
	pAdapt->IntReq.NdisRequest.DATA.SET_INFORMATION.Oid = Oid;
	pAdapt->IntReq.NdisRequest.DATA.SET_INFORMATION.InformationBuffer = InformationBuffer;
	pAdapt->IntReq.NdisRequest.DATA.SET_INFORMATION.InformationBufferLength = InformationBufferLength;
	pAdapt->BytesNeeded = BytesNeeded;
	pAdapt->BytesReadOrWritten = BytesRead;

	NdisAcquireSpinLock(&pAdapt->Lock);     
	if (pAdapt->UnbindingInProcess == TRUE){
		NdisReleaseSpinLock(&pAdapt->Lock);
		Status = NDIS_STATUS_FAILURE;
		goto finish;
	}

	if ((pAdapt->natpDeviceState > NdisDeviceStateD0) 
		&& (pAdapt->StandingBy == FALSE)){
		pAdapt->QueuedRequest = TRUE;
		NdisReleaseSpinLock(&pAdapt->Lock);
		Status = NDIS_STATUS_PENDING;
		goto finish;
	}

	if (pAdapt->StandingBy == TRUE){
		NdisReleaseSpinLock(&pAdapt->Lock);
		Status = NDIS_STATUS_FAILURE;
		goto finish;
	}
	pAdapt->OutstandingRequests = TRUE;

	NdisReleaseSpinLock(&pAdapt->Lock);

	if(OID_TCP_TASK_OFFLOAD == Oid){
		
		Status = NDIS_STATUS_PENDING;
		goto finish;
	}

	NdisRequest(
		&Status,
		pAdapt->BindingHandle,
		&pAdapt->IntReq.NdisRequest
		);

	if (Status != NDIS_STATUS_PENDING){
		*BytesRead = pAdapt->IntReq.NdisRequest.DATA.SET_INFORMATION.BytesRead;
		*BytesNeeded = pAdapt->IntReq.NdisRequest.DATA.SET_INFORMATION.BytesNeeded;
		pAdapt->OutstandingRequests = FALSE;
	}

finish:

	return Status;
}


VOID
	natmProcessSetPowerOid(
		IN OUT PNDIS_STATUS pNdisStatus,
		IN PFILTER_ADAPTER pAdapt,
		IN PVOID InformationBuffer,
		IN ULONG InformationBufferLength,
		OUT PULONG BytesRead,
		OUT PULONG BytesNeeded
		)
{
	NDIS_DEVICE_POWER_STATE NewDeviceState;

	*pNdisStatus = NDIS_STATUS_FAILURE;

	__try
	{
		if (InformationBufferLength < sizeof(NDIS_DEVICE_POWER_STATE)){
			*pNdisStatus = NDIS_STATUS_INVALID_LENGTH;
			__leave;
		}

		NewDeviceState = (*(PNDIS_DEVICE_POWER_STATE)InformationBuffer);

		if ((pAdapt->natmDeviceState > NdisDeviceStateD0) && (NewDeviceState != NdisDeviceStateD0)){

			*pNdisStatus = NDIS_STATUS_FAILURE;
			__leave;
		}

		if (pAdapt->natmDeviceState == NdisDeviceStateD0 && NewDeviceState > NdisDeviceStateD0)
			pAdapt->StandingBy = TRUE;

		if (pAdapt->natmDeviceState > NdisDeviceStateD0 &&  NewDeviceState == NdisDeviceStateD0)
			pAdapt->StandingBy = FALSE;

		pAdapt->natmDeviceState = NewDeviceState;

		*pNdisStatus = NDIS_STATUS_SUCCESS;

	}
	__finally{
	}

	if (*pNdisStatus == NDIS_STATUS_SUCCESS){

		if (pAdapt->StandingBy == FALSE){
			if (pAdapt->LastIndicatedStatus != pAdapt->LatestUnIndicateStatus){

				NdisMIndicateStatus(
					pAdapt->MiniportHandle,
					pAdapt->LatestUnIndicateStatus,
					(PVOID)NULL,
					0
					);
				NdisMIndicateStatusComplete(pAdapt->MiniportHandle);
				pAdapt->LastIndicatedStatus = pAdapt->LatestUnIndicateStatus;
			}
		}else
			pAdapt->LatestUnIndicateStatus = pAdapt->LastIndicatedStatus;
		*BytesRead = sizeof(NDIS_DEVICE_POWER_STATE);
		*BytesNeeded = 0;
	}else{
		*BytesRead = 0;
		*BytesNeeded = sizeof (NDIS_DEVICE_POWER_STATE);
	}
}

VOID 
	natmFreeBuffers (
		IN OUT PNDIS_PACKET Packet
		)
{
	UINT nDataSize, nBufferCount;
	PNDIS_BUFFER pBuffer;

	NdisQueryPacket(
		(PNDIS_PACKET )Packet,
		(PUINT )NULL,
		(PUINT )&nBufferCount,
		&pBuffer,
		&nDataSize
		);

	while( nBufferCount-- > 0 ){
		NdisUnchainBufferAtFront ( Packet, &pBuffer );
		NdisFreeBuffer ( pBuffer );
	}
}

VOID
	natmReturnPacket(
		IN NDIS_HANDLE MiniportAdapterContext,
		IN PNDIS_PACKET	Packet
		)
{
	PFILTER_ADAPTER pAdapt;
	PNDIS_PACKET OrgPacket = NULL;
	NDIS_HANDLE pPacketPool;

	pAdapt = (PFILTER_ADAPTER)MiniportAdapterContext;

	pPacketPool = NdisGetPoolFromPacket( Packet );

	if (pPacketPool == pAdapt->RcvPP1){

		OrgPacket = *(PVOID*)Packet->MiniportReserved;
		NdisFreePacket(Packet);

	}else if (pPacketPool == pAdapt->RcvPP2){

		FLT_PKT *pFltPkt = *(PVOID*)Packet->MiniportReserved;

		ASSERT(pFltPkt);

		OrgPacket = pFltPkt->pOrgPkt;

		ASSERT(OrgPacket);

		natmFreeBuffers(Packet);

		NdisFreePacket(Packet);

		FreeFltPkt(pFltPkt);

	}else{

		NdisReturnPackets(&Packet, 1);
		OrgPacket = NULL;
	}

	if ( NULL != OrgPacket)
		NdisReturnPackets(&OrgPacket, 1);
}

NDIS_STATUS
	natmTransferData(
		OUT PNDIS_PACKET Packet,
		OUT PUINT BytesTransferred,
		IN NDIS_HANDLE MiniportAdapterContext,
		IN NDIS_HANDLE MiniportReceiveContext,
		IN UINT ByteOffset,
		IN UINT BytesToTransfer
		)
{
	PFILTER_ADAPTER pAdapt;
	NDIS_STATUS Status;

	pAdapt = (PFILTER_ADAPTER)MiniportAdapterContext;

	if (IsIMDeviceStateOn(pAdapt) == FALSE)
		return NDIS_STATUS_FAILURE;

	NdisTransferData(
		&Status,
		pAdapt->BindingHandle,
		MiniportReceiveContext,
		ByteOffset,
		BytesToTransfer,
		Packet,
		BytesTransferred
		);

	return Status;
}

void
	natmHalt(
		IN NDIS_HANDLE MiniportAdapterContext
		)
{
	PFILTER_ADAPTER pAdapt;
	NDIS_STATUS Status;

	pAdapt = (PFILTER_ADAPTER)MiniportAdapterContext;

	NdisAcquireSpinLock(&g_AdapterListLock);
	RemoveEntryList(&pAdapt->ctrl.ListEntry);
	NdisReleaseSpinLock(&g_AdapterListLock);

	natpDeregisterDevice();

	if (pAdapt->BindingHandle != NULL){

		NdisResetEvent(&pAdapt->Event);
		NdisCloseAdapter(&Status, pAdapt->BindingHandle);

		if (Status == NDIS_STATUS_PENDING){
			NdisWaitEvent(&pAdapt->Event, 0);
			Status = pAdapt->Status;
		}

		pAdapt->BindingHandle = NULL;
	}

	natFreeAllItems(&pAdapt->ctrl);
	natmFreeAllPacketPools(pAdapt);

	if (pAdapt)
	        NdisFreeSpinLock(&pAdapt->Lock);

	NdisFreeMemory(pAdapt, 0, 0);
}

VOID
	natmFreeAllPacketPools(
		IN PFILTER_ADAPTER pAdapt
		)
{
	if (pAdapt->RcvPP1 != NULL){
		NdisFreePacketPool(pAdapt->RcvPP1);
		pAdapt->RcvPP1 = NULL;
	}

	if (pAdapt->RcvPP2 != NULL){
		NdisFreePacketPool(pAdapt->RcvPP2);
		pAdapt->RcvPP2 = NULL;
	}

	if (pAdapt->SndPP1 != NULL){
		NdisFreePacketPool(pAdapt->SndPP1);
		pAdapt->SndPP1 = NULL;
	}

	if (pAdapt->SndPP2 != NULL){
		NdisFreePacketPool(pAdapt->SndPP2);
		pAdapt->RcvPP2 = NULL;
	}

	if (pAdapt->SndBP != NULL){
		NdisFreeBufferPool(pAdapt->SndBP);
		pAdapt->SndBP = NULL;
	}

	if (pAdapt->RcvBP != NULL){
		NdisFreeBufferPool(pAdapt->RcvBP);
		pAdapt->RcvBP = NULL;
	}
}

VOID
natmCancelSendPackets(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PVOID CancelId
    )
{
    PFILTER_ADAPTER pAdapt = (PFILTER_ADAPTER)MiniportAdapterContext;

    NdisCancelSendPackets(pAdapt->BindingHandle, CancelId);
    return;
}

VOID
natmDevicePnPEvent(
    IN NDIS_HANDLE              MiniportAdapterContext,
    IN NDIS_DEVICE_PNP_EVENT    DevicePnPEvent,
    IN PVOID                    InformationBuffer,
    IN ULONG                    InformationBufferLength
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(DevicePnPEvent);
    UNREFERENCED_PARAMETER(InformationBuffer);
    UNREFERENCED_PARAMETER(InformationBufferLength);
    
    return;
}

VOID
natmAdapterShutdown(
    IN NDIS_HANDLE MiniportAdapterContext
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
}

NDIS_STATUS
	natmSendFltPacket(
		IN PFILTER_COMMON_CONTROL_BLOCK pAdaptControl,
		IN FLT_PKT* pFltPkt
		)
{
	PFILTER_ADAPTER		pAdapt;
	NDIS_STATUS       Status;
	PVOID         		MediaSpecificInfo = NULL;
	ULONG         		MediaSpecificInfoSize = 0;
	PNDIS_PACKET			pNewPacket;
	PNDIS_BUFFER			pNewBuffer = NULL;

	pAdapt = CONTAINING_RECORD(pAdaptControl, FILTER_ADAPTER, ctrl);

	NdisAcquireSpinLock(&pAdapt->Lock);
	if (pAdapt->natpDeviceState > NdisDeviceStateD0 || 
		pAdapt->natmDeviceState > NdisDeviceStateD0){

		ASSERT(FALSE);
		NdisReleaseSpinLock(&pAdapt->Lock);
		return NDIS_STATUS_FAILURE;
	}
	NdisReleaseSpinLock(&pAdapt->Lock);

	ASSERT(pFltPkt->pBuf);

	NdisAllocatePacket(
		&Status,
		&pNewPacket,
		pAdapt->SndPP2
		);

	if (NDIS_STATUS_SUCCESS != Status)
		return Status;

	*((PVOID*)pNewPacket->ProtocolReserved) = pFltPkt;

	NdisAllocateBuffer(
		&Status,
		&pNewBuffer,
		pAdapt->SndBP,
		pFltPkt->pBuf,
		pFltPkt->uLen
		);

	if (NDIS_STATUS_SUCCESS != Status){

		ASSERT(FALSE);

		NdisReinitializePacket (pNewPacket);
		NdisFreePacket (pNewPacket);
		return Status;
	}

	NdisChainBufferAtFront(pNewPacket, pNewBuffer);

	NdisSetPacketFlags(pNewPacket, NDIS_FLAGS_DONT_LOOPBACK);

	InterlockedIncrement(&pAdapt->SendPending);
	NdisSendPackets(
			pAdapt->BindingHandle,
			&pNewPacket,
			1
			);

    return NDIS_STATUS_SUCCESS;
}
