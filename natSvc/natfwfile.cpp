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

#include <Ws2tcpip.h>
#include <wtypes.h>
#include <io.h>
#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <iphlpapi.h>

#include "..\natDrvCommon\natdrvio.h"
#include "..\natDrvCommon\protos.h"
#include "natlog.h"
#include "natcfg.h"

#define NAT_CONFIG_FILE "nat1x1.ini"
#define FIREWAL_CONFIG_FILE "firewall.ini"
#define CUSTOMER_ADAPTER_NAME_W L"Customer Interface"

extern NATCL_CONFIG nam_cfg;

BOOLEAN
bLoadNatTable(ULONGLONG *pCustomerMac)
{
    NATDRV_IO_NAT_ENTRY nat_entry;
    BOOLEAN bOk = FALSE;
    char buf[255];
    char prvIpStr[255];
    char pubIpStr[255];
    char *s, *c;
    int line = 0;
    char file_name[MAX_PATH];

    sprintf(file_name, "%s\\%s", nam_cfg.sGetBinPath(), NAT_CONFIG_FILE);

    FILE* f = fopen(file_name, "rt");
    if (NULL == f) {

        LOG_ERROR(("Failed to open '%s' file", file_name));
        return FALSE;
    }

    nat_entry.uMacAddr = *pCustomerMac;

    while (fgets(buf, sizeof(buf) - 1, f)) {

        line++;
        s = buf;

        while (' ' == *s || '\t' == *s) s++;

        for (c = s; *c; c++) {
            switch (*c) {
            case '\n':
            case '\r':
                *c = ' ';
                break;
            case '#':
            case ';':
                *c = '\0';
                break;
            }
        }

        if (!strlen(s))
            continue;

        // 
        // Configuration file has the following format:
        // #Private IP        Public IP 
        //	172.17.78.2        10.5.1.195 
        //
        if (2 != sscanf(s, "%s%s", prvIpStr, pubIpStr)) {

            LOG_ERROR(("'%s'(%d) : Error while parsing string '%s'", file_name, line, buf));
            continue;
        }

        if (1 != inet_pton(AF_INET, prvIpStr, &nat_entry.PrvIpAddr)) {

            LOG_ERROR(("'%s'(%d) : Invalid IP address detected while parsing string '%s'", file_name, line, buf));
            continue;
        }

        if (1 != inet_pton(AF_INET, pubIpStr, &nat_entry.PubIpAddr)) {
            LOG_ERROR(("'%s'(%d) : Invalid IP address detected while parsing string '%s'", file_name, line, buf));
            continue;
        }

        if (!natbAddNATEntry(&nat_entry)) {
            LOG_ERROR(("'%s'(%d) : Failed to add NAT entry to kernel : '%s'", file_name, line, buf));
            continue;
        }
    }

    bOk = TRUE;

    fclose(f);

    return bOk;
}

ULONG
uOnesToMask(ULONG ones)
{
    ULONG netmask;

    if (0 == ones)
        return 0;

    netmask = -1 << (32 - ones);
    netmask = htonl(netmask);

    return netmask;
}

BOOLEAN
bLoadFirewall(ULONGLONG *pCustomerMac)
{
    NATDRV_IO_FW_RULE fw_entry;
    BOOLEAN bOk = FALSE;
    char buf[255];
    char prvIpStr[255];
    char pubIpStr[255];
    char portStr[255];
    char protoStr[255];
    char directionStr[255];
    char *s, *c;
    int line = 0;
    char file_name[MAX_PATH];

    sprintf(file_name, "%s\\%s", nam_cfg.sGetBinPath(), FIREWAL_CONFIG_FILE);

    FILE* f = fopen(file_name, "rt");
    if (NULL == f) {

        LOG_ERROR(("Failed to open '%s' file", file_name));
        return FALSE;
    }

    fw_entry.uMacAddr = *pCustomerMac;

    while (fgets(buf, sizeof(buf) - 1, f)) {

        line++;
        s = buf;

        for (c = s; *c; c++) {
            switch (*c) {
            case '\n':
            case '\r':
                *c = ' ';
                break;
            case '#':
            case ';':
                *c = '\0';
                break;
            }
        }

        while (' ' == *s || '\t' == *s) s++;

        if (!strlen(s))
            continue;

        // 
        // Configuration file has the following format:
        // #Private IP        Public IP       Proto      Port(s)                  Direction 
        // 172.17.78.2/32     10.5.1.192/32   tcp        20,21,23,5900,3389       both/in/out
        //
        if (5 != sscanf(s, "%s%s%s%s%s", prvIpStr, pubIpStr, protoStr, portStr, directionStr)) {

            LOG_ERROR(("'%s'(%d) : Error while parsing string '%s'", file_name, line, buf));
            continue;
        }

        if (NULL == (c = _tcschr(prvIpStr, '/'))) {

            LOG_ERROR(("'%s'(%d) : Invalid IP address mask detected while parsing string '%s'", file_name, line, buf));
            continue;
        }
        *c++ = 0;
        fw_entry.uPrvMask = atoi(c);
        if (fw_entry.uPrvMask > 32) {

            LOG_ERROR(("'%s'(%d) : Invalid IP address mask detected while parsing string '%s'", file_name, line, buf));
            continue;
        }
        fw_entry.uPrvMask = uOnesToMask(fw_entry.uPrvMask);

        if (NULL == (c = _tcschr(pubIpStr, '/'))) {

            LOG_ERROR(("'%s'(%d) : Invalid IP address mask detected while parsing string '%s'", file_name, line, buf));
            continue;
        }
        *c++ = 0;
        fw_entry.uPubMask = atoi(c);
        if (fw_entry.uPubMask > 32) {

            LOG_ERROR(("'%s'(%d) : Invalid IP address mask detected while parsing string '%s'", file_name, line, buf));
            continue;
        }
        fw_entry.uPubMask = uOnesToMask(fw_entry.uPubMask);

        if (1 != inet_pton(AF_INET, prvIpStr, &fw_entry.PrvIpAddr)) {

            LOG_ERROR(("'%s'(%d) : Invalid IP address detected while parsing string '%s'", file_name, line, buf));
            continue;
        }

        if (1 != inet_pton(AF_INET, pubIpStr, &fw_entry.PubIpAddr)) {
            LOG_ERROR(("'%s'(%d) : Invalid IP address detected while parsing string '%s'", file_name, line, buf));
            continue;
        }

        if ((fw_entry.uPrvIpAddr & fw_entry.uPrvMask) != fw_entry.uPrvIpAddr) {
            LOG_ERROR(("'%s'(%d) : Invalid IP address & mask detected while parsing string '%s'", file_name, line, buf));
            continue;
        }

        if ((fw_entry.uPubIpAddr & fw_entry.uPubMask) != fw_entry.uPubIpAddr) {
            LOG_ERROR(("'%s'(%d) : Invalid IP address & mask detected while parsing string '%s'", file_name, line, buf));
            continue;
        }


        if (!_tcsicmp(protoStr, "tcp")) {

            fw_entry.uProtocol = IPPROTO_TCP;

        }
        else if (!_tcsicmp(protoStr, "udp")) {

            fw_entry.uProtocol = IPPROTO_UDP;

        }
        else if (!_tcsicmp(protoStr, "icmp")) {

            fw_entry.uProtocol = IPPROTO_ICMP;
        }
        else {

            LOG_ERROR(("'%s'(%d) : Invalid protocol detected while parsing string '%s'", file_name, line, buf));
            continue;
        }

        BOOLEAN bOut, bIn;

        if (!_tcsicmp(directionStr, "in")) {

            bOut = FALSE;
            bIn = TRUE;

        }
        else if (!_tcsicmp(directionStr, "out")) {

            bOut = TRUE;
            bIn = FALSE;

        }
        else if (!_tcsicmp(directionStr, "both")) {
            bOut = TRUE;
            bIn = TRUE;
        }
        else {

            LOG_ERROR(("'%s'(%d) : Failed to add firewall rule entry to kernel : '%s'", file_name, line, buf));
            continue;
        }

        //
        // parse ports
        //
        c = portStr;
        do {

            if (c != portStr)
                *c++ = 0;

            fw_entry.uPort = ntohs((USHORT)atoi(c));

            if (bOut) {

                fw_entry.uOut = TRUE;
                if (!natbAddFirewallRule(&fw_entry)) {
                    LOG_ERROR(("'%s'(%d) : Failed to add firewall rule entry to kernel : '%s'", file_name, line, buf));
                    continue;
                }
            }

            if (bIn) {

                fw_entry.uOut = FALSE;
                if (!natbAddFirewallRule(&fw_entry)) {
                    LOG_ERROR(("'%s'(%d) : Failed to add firewall rule entry to kernel : '%s'", file_name, line, buf));
                    continue;
                }
            }

        } while (NULL != (c = _tcschr(c, ',')));

    } // while(fgets...

    bOk = TRUE;

    fclose(f);

    return bOk;
}

BOOLEAN
bInitHostAdapters(BOOLEAN bStart, ULONGLONG *pCustomerMac)
{
    BOOLEAN bOk = FALSE;
    ULONG err;
    ULONG ulReqSize;
    PIP_ADAPTER_ADDRESSES pAdapterAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pAdapter;
    ULONG uAdapterCount = 0;
    ULONG ulOutBufLen = 0;

    ulReqSize = 0;

    err = GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL,
        NULL,
        &ulReqSize);

    if (err != ERROR_BUFFER_OVERFLOW) {

        LOG_ERROR("GetAdaptersAddresses failed");
        goto finish;
    }

    ulReqSize = ulReqSize * 2;

    pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(ulReqSize);
    if (pAdapterAddresses == NULL)
    {
        err = ERROR_NOT_ENOUGH_MEMORY;
        LOG_ERROR("Not enough memory");
        goto finish;
    }

    err = GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL,
        pAdapterAddresses,
        &ulReqSize);

    if (err != NO_ERROR)
    {
        LOG_ERROR("GetAdaptersAddresses failed");
        goto finish;
    }

    //
    // Simply count the number of adapters detected
    //
    uAdapterCount = 0;
    for (pAdapter = pAdapterAddresses; pAdapter; pAdapter = pAdapter->Next) {

        if (pAdapter->IfType != MIB_IF_TYPE_ETHERNET ||
            pAdapter->PhysicalAddressLength != 6 ||
            0 == pAdapter->IfIndex
            )
        {

            continue;
        }

        NATDRV_IO_INIT init_entry;
        memset(&init_entry, 0, sizeof(init_entry));

        memcpy(&init_entry.uMacAddr, pAdapter->PhysicalAddress, pAdapter->PhysicalAddressLength);

        if (!_wcsnicmp(pAdapter->FriendlyName, CUSTOMER_ADAPTER_NAME_W, wcslen(CUSTOMER_ADAPTER_NAME_W))) {

            bOk = TRUE;
            if (pCustomerMac) {
                *pCustomerMac = init_entry.uMacAddr;
            }

            init_entry.bFiltered = bStart;
        }

        init_entry.bStarted = bStart;

        if (!natbInit(&init_entry))
        {
            bOk = FALSE;
            LOG_ERROR("natbInit failed");
            goto finish;
        }

        uAdapterCount++;
    }

finish:

    if (NULL != pAdapterAddresses) {
        free(pAdapterAddresses);
    }

    return bOk;
}
