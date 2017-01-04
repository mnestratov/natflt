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

NTSTATUS
natpDispatch(
    IN PDEVICE_OBJECT    DeviceObject,
    IN PIRP              Irp
);

NDIS_STATUS
FilterRegisterDevice(
    VOID
)
{
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
    PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;
    PDRIVER_OBJECT                  DriverObject;

    NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION + 1) * sizeof(PDRIVER_DISPATCH));
    DispatchTable[IRP_MJ_CREATE] = natpDispatch;
    DispatchTable[IRP_MJ_CLEANUP] = natpDispatch;
    DispatchTable[IRP_MJ_CLOSE] = natpDispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = natpDispatch;
    DispatchTable[IRP_MJ_INTERNAL_DEVICE_CONTROL] = natpDispatch;

    NdisInitUnicodeString(&DeviceName, FILTER_NT_DEVICE_NAME);
    NdisInitUnicodeString(&DeviceLinkUnicodeString, FILTER_DOSDEVICE_NAME);

    //
    // Create a device object and register our dispatch handlers
    //
    NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));

    DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);

    DeviceAttribute.DeviceName = &DeviceName;
    DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
    DeviceAttribute.MajorFunctions = &DispatchTable[0];
    DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);

    Status = NdisRegisterDeviceEx(
        FilterDriverHandle,
        &DeviceAttribute,
        &DeviceObject,
        &NdisFilterDeviceHandle
    );


    if (Status == NDIS_STATUS_SUCCESS) {

        FilterDeviceExtension = NdisGetDeviceReservedExtension(DeviceObject);
        FilterDeviceExtension->Signature = 'FTDR';
        FilterDeviceExtension->Handle = FilterDriverHandle;

        // Workaround NDIS bug
        DriverObject = (PDRIVER_OBJECT)FilterDriverObject;
    }

    return Status;
}

VOID
FilterDeregisterDevice(
    IN VOID
)
{
    if (NdisFilterDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
    }
    NdisFilterDeviceHandle = NULL;
}
