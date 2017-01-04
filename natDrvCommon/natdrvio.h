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

#ifndef _NATDRV_IO_HEADER_
#define _NATDRV_IO_HEADER_

#define NATDRV_DEVICE_NAME_STR "natfwdrv"
#define NATDRV_SYMBOLICK_NAME_STR "\\\\.\\"NATDRV_DEVICE_NAME_STR

#define NATDRV_DEVICE_NAME_STR_W L"natfwdrv"


#define FILTER_NT_DEVICE_NAME  L"\\Device\\"NATDRV_DEVICE_NAME_STR_W
#define FILTER_DOSDEVICE_NAME  L"\\DosDevices\\Global\\"NATDRV_DEVICE_NAME_STR_W


#define NAT_DRV_DEVICE_ID			0x9ff6
#define NAT_FUNC_CODE				0x808


#define NATDRV_INIT_IOCTL		CTL_CODE(NAT_DRV_DEVICE_ID,	\
										 NAT_FUNC_CODE + 1,			\
										 METHOD_BUFFERED,			\
										 FILE_ANY_ACCESS)

#define NATDRV_RELEASE_IOCTL	CTL_CODE(NAT_DRV_DEVICE_ID,	\
										 NAT_FUNC_CODE + 2,			\
										 METHOD_BUFFERED,			\
										 FILE_ANY_ACCESS)


#define NATDRV_ADD_NAT_ENTRY_IOCTL		CTL_CODE(NAT_DRV_DEVICE_ID,	\
										 NAT_FUNC_CODE + 3,			\
										 METHOD_BUFFERED,			\
										 FILE_ANY_ACCESS)

#define NATDRV_ADD_FW_ENTRY_IOCTL	CTL_CODE(NAT_DRV_DEVICE_ID,	\
										 NAT_FUNC_CODE + 4,			\
										 METHOD_BUFFERED,			\
										 FILE_ANY_ACCESS)


#pragma pack(push,1)

typedef struct _NATDRV_IO_INIT {
    ULONGLONG uMacAddr;
    ULONG bStarted;
    ULONG bFiltered;
}NATDRV_IO_INIT;

typedef struct _NATDRV_IO_FW_RULE {

    ULONGLONG uMacAddr;
    ULONG uPrvIpAddr;
    ULONG uPrvMask;
    ULONG uPubIpAddr;
    ULONG uPubMask;
    ULONG uProtocol;
    ULONG uPort;
    ULONG uOut;

}NATDRV_IO_FW_RULE;

typedef struct _NATDRV_IO_NAT_ENTRY {

    ULONGLONG uMacAddr;
    ULONG uPrvIpAddr;
    ULONG uPubIpAddr;

}NATDRV_IO_NAT_ENTRY;


#pragma pack(pop)

BOOLEAN
natbOpenFile();

void
natvCloseFile();

BOOLEAN
natbInit(NATDRV_IO_INIT *pInit);

BOOLEAN
natbAddNATEntry(NATDRV_IO_NAT_ENTRY *pNatEntry);

BOOLEAN
natbAddFirewallRule(NATDRV_IO_FW_RULE *pRule);

BOOLEAN
natbRelease();


#endif // _NATDRV_DRV_IO_HEADER_
