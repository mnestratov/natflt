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

#define _CRT_SECURE_NO_WARNINGS

#include <tchar.h>
#include <wtypes.h>
#include <winioctl.h>
#include <winbase.h>

#include "..\natDrvCommon\natdrvio.h"
#include "natlog.h"

HANDLE		g_hDriver = NULL;

BOOLEAN 
	natbOpenFile()
{
	g_hDriver = CreateFile( _T(NATDRV_SYMBOLICK_NAME_STR),
                  GENERIC_READ | GENERIC_WRITE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                  NULL,
                  OPEN_EXISTING,
				  FILE_ATTRIBUTE_NORMAL,
                  NULL
                  );

	
	if (NULL == g_hDriver ||  INVALID_HANDLE_VALUE == g_hDriver )	
		return FALSE;

	
	return TRUE;
}

void 
	natvCloseFile()
{
	if (NULL == g_hDriver ||  INVALID_HANDLE_VALUE == g_hDriver )
		return;
		
	CloseHandle(g_hDriver);
	g_hDriver = NULL;
}

BOOLEAN 
	natbInit(NATDRV_IO_INIT *pInit)
{
	ULONG res_size;

	if (NULL == g_hDriver ||  INVALID_HANDLE_VALUE == g_hDriver )
		return FALSE;
	
	return DeviceIoControl(g_hDriver,
					NATDRV_INIT_IOCTL,
					pInit, sizeof(*pInit),
					NULL, 0,
					&res_size,
					NULL);
}

BOOLEAN 
	natbRelease()
{
	ULONG res_size;

	if (NULL == g_hDriver ||  INVALID_HANDLE_VALUE == g_hDriver )
		return FALSE;
	
	return DeviceIoControl(g_hDriver,
					NATDRV_RELEASE_IOCTL,
					NULL, 0,
					NULL, 0,
					&res_size,
					NULL);
}

BOOLEAN 
	natbAddNATEntry(NATDRV_IO_NAT_ENTRY *pNatEntry)
{
	BOOLEAN bOk;
	ULONG res_size;

	if (NULL == g_hDriver ||  INVALID_HANDLE_VALUE == g_hDriver )
		return FALSE;

	natvLog(NATLOG_NAT, "--------------------");
	natvLog(NATLOG_NAT, "NAT 1x1 ENTRY");

	natvLog(NATLOG_NAT,"%20s: %02x:%02x:%02x:%02x:%02x:%02x", "Adapter MAC address", NATSVC_PRINT_MAC(&pNatEntry->uMacAddr));

	natvLog(NATLOG_NAT, "%20s: %s",
		"PRIVATE",
		inet_ntoa(*((in_addr*)&pNatEntry->uPrvIpAddr)));

	natvLog(NATLOG_NAT, "%20s: %s",
		"PUBLIC",
		inet_ntoa(*((in_addr*)&pNatEntry->uPubIpAddr)));

	bOk = DeviceIoControl(g_hDriver,
					NATDRV_ADD_NAT_ENTRY_IOCTL,
					pNatEntry, sizeof(*pNatEntry),
					NULL, 0,
					&res_size,
					NULL);

	natvLog(NATLOG_NAT, "%20s: %s", "OPERATION STATUS", bOk ? "OK" : "Failed");
	natvLog(NATLOG_NAT, "--------------------");

	return bOk;
}

BOOLEAN 
	natbAddFirewallRule(NATDRV_IO_FW_RULE *pRule)
{
	ULONG res_size;
	BOOLEAN bOk;

	if (NULL == g_hDriver ||  INVALID_HANDLE_VALUE == g_hDriver )
		return FALSE;

	natvLog(NATLOG_RULE, "--------------------");
	natvLog(NATLOG_RULE, "FIREWALL RULE");

	natvLog(NATLOG_RULE, "%20s: %02x:%02x:%02x:%02x:%02x:%02x",
		"Adapter MAC address",
		NATSVC_PRINT_MAC(&pRule->uMacAddr));
	natvLog(NATLOG_RULE, "%20s: %s",
		"ALLOW",
		pRule->uOut ? "Outgoing" : "Incoming");
	switch(pRule->uProtocol){
	case IPPROTO_TCP:
		natvLog(NATLOG_RULE, "%20s: %s",
			"PROTOCOL",
			"TCP");
		break;
	case IPPROTO_UDP:
		natvLog(NATLOG_RULE,"%20s: %s",
			"PROTOCOL",
			"UDP");
		break;
	case IPPROTO_ICMP:
		natvLog(NATLOG_RULE,"%20s: %s",
			"PROTOCOL",
			"ICMP");
		break;
	}
	natvLog(NATLOG_RULE,"%20s: %s",
		"PRIVATE IP ADDRESS",
		inet_ntoa(*((in_addr*)&pRule->uPrvIpAddr)));

	natvLog(NATLOG_RULE,"%20s: %s",
		"PRIVATE MASK",
		inet_ntoa(*((in_addr*)&pRule->uPrvMask)));

	natvLog(NATLOG_RULE,"%20s: %s",
		"PUBLIC IP ADDRESS",
		inet_ntoa(*((in_addr*)&pRule->uPubIpAddr)));

	natvLog(NATLOG_RULE,"%20s: %s",
		"PUBLIC MASK",
		inet_ntoa(*((in_addr*)&pRule->uPubMask)));

	natvLog(NATLOG_RULE,"%20s: %u",
		"PORT",
		ntohs((USHORT)pRule->uPort));

	bOk = DeviceIoControl(g_hDriver,
					NATDRV_ADD_FW_ENTRY_IOCTL,
					pRule, sizeof(*pRule),
					NULL, 0,
					&res_size,
					NULL);

	natvLog(NATLOG_RULE,"%20s: %s", "OPERATION STATUS", bOk ? "OK" : "Failed");
	natvLog(NATLOG_RULE,"--------------------");

	return bOk;
}
