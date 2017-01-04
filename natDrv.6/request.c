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
FilterOidRequest(
		IN NDIS_HANDLE         FilterModuleContext,
		IN PNDIS_OID_REQUEST   Request
		)
{
	PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)FilterModuleContext;
	NDIS_STATUS Status = NDIS_STATUS_FAILURE;
	PNDIS_OID_REQUEST ClonedRequest = NULL;
	PFILTER_REQUEST_CONTEXT pContext = NULL;
	BOOLEAN bSubmit = FALSE;

	if(NdisRequestSetInformation == Request->RequestType || 
		NdisRequestQueryInformation == Request->RequestType){

		if(OID_TCP_OFFLOAD_PARAMETERS == Request->DATA.QUERY_INFORMATION.Oid ||
			OID_TCP_OFFLOAD_HARDWARE_CAPABILITIES == Request->DATA.QUERY_INFORMATION.Oid ||
			OID_TCP_OFFLOAD_CURRENT_CONFIG == Request->DATA.QUERY_INFORMATION.Oid
			){
			Status = NDIS_STATUS_NOT_SUPPORTED;
			goto finish;
		}
	}

	Status = NdisAllocateCloneOidRequest(pAdapter->FilterHandle,
										Request,
										FILTER_TAG,
										&ClonedRequest);

	if (Status != NDIS_STATUS_SUCCESS)
		goto finish;

	bSubmit = TRUE;

	ClonedRequest->RequestId = Request->RequestId;	

	pContext = (PFILTER_REQUEST_CONTEXT)(&ClonedRequest->SourceReserved[0]);
	*pContext = (NDIS_OID_REQUEST*)&(pAdapter->m_IntReq);
	pAdapter->m_IntReq.pOrigReq = Request;	
	pAdapter->m_IntReq.pReq = ClonedRequest;

	pAdapter->m_IntReq.bLocal = FALSE;
	pAdapter->m_IntReq.Status = NDIS_STATUS_PENDING;	

	Status = NdisFOidRequest(pAdapter->FilterHandle, ClonedRequest);

	if (Status != NDIS_STATUS_PENDING){
		FilterOidRequestComplete(pAdapter, ClonedRequest, Status);
		Status = NDIS_STATUS_PENDING;
	}

finish:

	if (bSubmit)
		return Status;

	switch(Request->RequestType){
		case NdisRequestMethod:
			Request->DATA.METHOD_INFORMATION.BytesRead = 0;
			Request->DATA.METHOD_INFORMATION.BytesNeeded = 0; 
			Request->DATA.METHOD_INFORMATION.BytesWritten = 0; 
			break;

		case NdisRequestSetInformation:
			Request->DATA.SET_INFORMATION.BytesRead = 0;
			Request->DATA.SET_INFORMATION.BytesNeeded = 0; 
			break;

		case NdisRequestQueryInformation:
		case NdisRequestQueryStatistics:

			break;		
		default:
			Request->DATA.QUERY_INFORMATION.BytesWritten = 0;
			Request->DATA.QUERY_INFORMATION.BytesNeeded = 0; 
			break;
	}

	return Status;
}

VOID
FilterCancelOidRequest(
		IN NDIS_HANDLE	FilterModuleContext,
		IN PVOID		RequestId
		)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)FilterModuleContext;
    PNDIS_OID_REQUEST OriginalRequest = NULL;

    NdisAcquireSpinLock(&pAdapter->Lock);

	OriginalRequest = pAdapter->m_IntReq.pOrigReq;
    if ((OriginalRequest != NULL) && (OriginalRequest->RequestId == RequestId)){
        NdisReleaseSpinLock(&pAdapter->Lock);
        NdisFCancelOidRequest(pAdapter->FilterHandle, RequestId);
    }else
        NdisReleaseSpinLock(&pAdapter->Lock);
}

VOID
FilterOidRequestComplete(
		IN NDIS_HANDLE         FilterModuleContext,
		IN PNDIS_OID_REQUEST   Request,
		IN NDIS_STATUS         Status
		)
{
    PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)FilterModuleContext;
    PNDIS_OID_REQUEST OriginalRequest;
	PINTERNAL_OID_REQUEST pInternalRequest;
    PFILTER_REQUEST_CONTEXT Context;

	NdisAcquireSpinLock(&pAdapter->Lock);

    Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);
    pInternalRequest = (PINTERNAL_OID_REQUEST)(*Context);

	if (pInternalRequest->bLocal){
		NdisReleaseSpinLock(&pAdapter->Lock);
		NdisFreeMemory(pInternalRequest, 0, 0);
		return;
	}
	OriginalRequest = pInternalRequest->pOrigReq;
    pAdapter->m_IntReq.Status = Status;
	pAdapter->m_IntReq.pOrigReq = NULL;
	pAdapter->m_IntReq.pReq = NULL;
	
    NdisReleaseSpinLock(&pAdapter->Lock);

    switch(Request->RequestType){
        case NdisRequestMethod:
            OriginalRequest->DATA.METHOD_INFORMATION.OutputBufferLength =  Request->DATA.METHOD_INFORMATION.OutputBufferLength;
            OriginalRequest->DATA.METHOD_INFORMATION.BytesRead = Request->DATA.METHOD_INFORMATION.BytesRead;
            OriginalRequest->DATA.METHOD_INFORMATION.BytesNeeded = Request->DATA.METHOD_INFORMATION.BytesNeeded; 
            OriginalRequest->DATA.METHOD_INFORMATION.BytesWritten = Request->DATA.METHOD_INFORMATION.BytesWritten; 
            break;

        case NdisRequestSetInformation:
            OriginalRequest->DATA.SET_INFORMATION.BytesRead = Request->DATA.SET_INFORMATION.BytesRead;
            OriginalRequest->DATA.SET_INFORMATION.BytesNeeded = Request->DATA.SET_INFORMATION.BytesNeeded; 
            break;

        case NdisRequestQueryInformation:
        case NdisRequestQueryStatistics:
        default:
            OriginalRequest->DATA.QUERY_INFORMATION.BytesWritten = Request->DATA.QUERY_INFORMATION.BytesWritten;
            OriginalRequest->DATA.QUERY_INFORMATION.BytesNeeded = Request->DATA.QUERY_INFORMATION.BytesNeeded;
            break;
    }
    (*Context) = NULL;
    NdisFreeCloneOidRequest(pAdapter->FilterHandle, Request);

    NdisFOidRequestComplete(pAdapter->FilterHandle, OriginalRequest, Status);
    
}

NDIS_STATUS
FilterDoInternalRequest(
    IN PNETGW_ADAPT FilterModuleContext,
    IN NDIS_REQUEST_TYPE RequestType,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    IN ULONG OutputBufferLength
    )
{
	PNETGW_ADAPT pAdapter = (PNETGW_ADAPT)FilterModuleContext;
	PFILTER_REQUEST_CONTEXT pContext;
	PINTERNAL_OID_REQUEST pInternalRequest;
    PNDIS_OID_REQUEST pNdisRequest = NULL;
    NDIS_STATUS Status;

	UNREFERENCED_PARAMETER(OutputBufferLength);

	pInternalRequest = (PINTERNAL_OID_REQUEST)NdisAllocateMemoryWithTagPriority(
			pAdapter->FilterHandle, sizeof(INTERNAL_OID_REQUEST), FILTER_TAG, NormalPoolPriority);
	if (pInternalRequest == NULL)
		return NDIS_STATUS_RESOURCES;
	NdisZeroMemory(pInternalRequest, sizeof(*pInternalRequest));

	pNdisRequest = &pInternalRequest->NdisReq;
	pNdisRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	pNdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	pNdisRequest->Header.Size = sizeof(NDIS_OID_REQUEST);
	pNdisRequest->RequestType = RequestType;

	pInternalRequest->bLocal = TRUE;
	pInternalRequest->pReq = pNdisRequest;
	pInternalRequest->pOrigReq = NULL;

	pContext = (PFILTER_REQUEST_CONTEXT)(&pNdisRequest->SourceReserved[0]);
	*pContext = (NDIS_OID_REQUEST*)pInternalRequest;

	pNdisRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	pNdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	pNdisRequest->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;
	pNdisRequest->RequestHandle = pAdapter->FilterHandle;
	pNdisRequest->SupportedRevision = NDIS_OID_REQUEST_REVISION_1;

	switch (RequestType){
	case NdisRequestQueryInformation:
             pNdisRequest->DATA.QUERY_INFORMATION.Oid = Oid;
             pNdisRequest->DATA.QUERY_INFORMATION.InformationBuffer =
                                    InformationBuffer;
             pNdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength =
                                    InformationBufferLength;
            break;

        case NdisRequestSetInformation:
             pNdisRequest->DATA.SET_INFORMATION.Oid = Oid;
             pNdisRequest->DATA.SET_INFORMATION.InformationBuffer =
                                    InformationBuffer;
             pNdisRequest->DATA.SET_INFORMATION.InformationBufferLength =
                                    InformationBufferLength;
            break;

        default:
            ASSERT(FALSE);
            break;
    }
	pNdisRequest->RequestId = (PVOID)FILTER_REQUEST_ID;

	Status = NdisFOidRequest(pAdapter->FilterHandle, pNdisRequest);

	if (Status != NDIS_STATUS_PENDING)
		FilterOidRequestComplete(pAdapter, pNdisRequest, Status);

	return Status;
}
