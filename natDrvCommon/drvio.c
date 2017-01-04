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

LIST_ENTRY			g_AdapterListHead;
NDIS_SPIN_LOCK		g_AdapterListLock;

#ifdef DBG
ULONG g_LogPktDrop = 1;
ULONG g_LogPktPass = 1;
ULONG g_LogPktNAT = 1;
#else
ULONG g_LogPktDrop = 0;
ULONG g_LogPktPass = 0;
ULONG g_LogPktNAT = 0;
#endif

BOOLEAN
natbInit(NATDRV_IO_INIT * pIoInit)
{
    PFILTER_COMMON_CONTROL_BLOCK	pAdapt;
    PLIST_ENTRY pAdapterEntry;

    NdisAcquireSpinLock(&g_AdapterListLock);
    for (pAdapterEntry = g_AdapterListHead.Flink; pAdapterEntry != &g_AdapterListHead; pAdapterEntry = pAdapterEntry->Flink) {

        pAdapt = CONTAINING_RECORD(pAdapterEntry, FILTER_COMMON_CONTROL_BLOCK, ListEntry);
        if (pAdapt->MacAddr.Val == pIoInit->uMacAddr) {

            pAdapt->bStarted = pIoInit->bStarted;
            pAdapt->bFiltered = pIoInit->bFiltered;
            break;
        }
    }
    NdisReleaseSpinLock(&g_AdapterListLock);

    return TRUE;
}

BOOLEAN
natbRelease()
{
    PFILTER_COMMON_CONTROL_BLOCK	pAdapt;
    PLIST_ENTRY pAdapterEntry;

    NdisAcquireSpinLock(&g_AdapterListLock);
    for (pAdapterEntry = g_AdapterListHead.Flink; pAdapterEntry != &g_AdapterListHead; pAdapterEntry = pAdapterEntry->Flink) {

        pAdapt = CONTAINING_RECORD(pAdapterEntry, FILTER_COMMON_CONTROL_BLOCK, ListEntry);

        pAdapt->bStarted = FALSE;
        pAdapt->bFiltered = FALSE;

        natFreeAllItems(pAdapt);

        natFreeAllFwSessionsAndRules(pAdapt);

    }
    NdisReleaseSpinLock(&g_AdapterListLock);

    return TRUE;
}

BOOLEAN
natbAddNATEntry(NATDRV_IO_NAT_ENTRY *pIoNatEntry)
{
    PFILTER_COMMON_CONTROL_BLOCK	pAdapt;
    PLIST_ENTRY pAdapterEntry;
    NAT_ENTRY *pNatEntry;
    BOOLEAN bOk = FALSE;

    NdisAcquireSpinLock(&g_AdapterListLock);
    for (pAdapterEntry = g_AdapterListHead.Flink; pAdapterEntry != &g_AdapterListHead; pAdapterEntry = pAdapterEntry->Flink) {

        pAdapt = CONTAINING_RECORD(pAdapterEntry, FILTER_COMMON_CONTROL_BLOCK, ListEntry);
        if (pAdapt->MacAddr.Val == pIoNatEntry->uMacAddr) {

            pNatEntry = ExAllocatePoolWithTag(0, sizeof(NAT_ENTRY), 'aN1N');
            ASSERT(pNatEntry);
            if (NULL == pNatEntry)
                break;

            pNatEntry->prvIpAddr = pIoNatEntry->uPrvIpAddr;
            pNatEntry->pubIpAddr = pIoNatEntry->uPubIpAddr;
            natInsertEntry(pAdapt, pNatEntry);

            bOk = TRUE;
            break;
        }
    }
    NdisReleaseSpinLock(&g_AdapterListLock);

    return bOk;
}

BOOLEAN
natbAddFirewallRule(NATDRV_IO_FW_RULE *pIoRule)

{
    PFILTER_COMMON_CONTROL_BLOCK	pAdapt;
    PLIST_ENTRY pAdapterEntry;
    PLIST_ENTRY pRuleHead;
    NDIS_SPIN_LOCK	*pRuleLock;
    PLIST_ENTRY pRuleEntry;
    FLT_RULE    *pRule;
    BOOLEAN bOk = FALSE;
    BOOLEAN bFound = FALSE;

    NdisAcquireSpinLock(&g_AdapterListLock);
    for (pAdapterEntry = g_AdapterListHead.Flink; pAdapterEntry != &g_AdapterListHead; pAdapterEntry = pAdapterEntry->Flink) {

        pAdapt = CONTAINING_RECORD(pAdapterEntry, FILTER_COMMON_CONTROL_BLOCK, ListEntry);
        if (pAdapt->MacAddr.Val != pIoRule->uMacAddr) {
            continue;
        }

        switch (pIoRule->uProtocol) {
        case IPPROTO_TCP:
            pRuleHead = &pAdapt->TcpRuleList;
            pRuleLock = &pAdapt->TcpRuleLock;
            break;
        case IPPROTO_UDP:
            pRuleHead = &pAdapt->UdpRuleList;
            pRuleLock = &pAdapt->UdpRuleLock;
            break;
        case IPPROTO_ICMP:
            pRuleHead = &pAdapt->IcmpRuleList;
            pRuleLock = &pAdapt->IcmpRuleLock;
            break;
        default:
            continue;
        }

        NdisAcquireSpinLock(pRuleLock);

        for (pRuleEntry = pRuleHead->Flink; pRuleEntry != pRuleHead; pRuleEntry = pRuleEntry->Flink) {

            pRule = CONTAINING_RECORD(pRuleEntry, FLT_RULE, ListEntry);
            if (pRule->out == pIoRule->uOut &&
                pRule->port == pIoRule->uPort &&
                (pRule->prvAddr & pRule->prvMask) == (pIoRule->uPrvIpAddr & pIoRule->uPrvMask) &&
                (pRule->pubAddr & pRule->pubMask) == (pIoRule->uPubIpAddr & pIoRule->uPubMask)
                )
            {

                bFound = TRUE;
                break;
            }
        }
        bOk = !bFound;

        if (bOk) {

            pRule = ExAllocatePoolWithTag(0, sizeof(FLT_RULE), 'lF1N');
            ASSERT(pRule);
            if (NULL == pRule)
                bOk = FALSE;
            else {

                char prvStr[30];
                char prvStrMask[30];
                char pubStr[30];
                char pubStrMask[30];

                PRINT_IP(prvStr, &pIoRule->uPrvIpAddr);
                PRINT_IP(prvStrMask, &pIoRule->uPrvMask);
                PRINT_IP(pubStr, &pIoRule->uPubIpAddr);
                PRINT_IP(pubStrMask, &pIoRule->uPubMask);
                DbgPrint("FIREWALL entry: %s prv=%s/%s pub=%s/%s PORT=%u PROTO=%u added\n",
                    pIoRule->uOut ? "OUTGOING" : "INCOMING",
                    prvStr, prvStrMask, pubStr, pubStrMask,
                    RtlUshortByteSwap(pIoRule->uPort),
                    pIoRule->uProtocol);

                pRule->out = pIoRule->uOut;
                pRule->port = pIoRule->uPort;
                pRule->prvMask = pIoRule->uPrvMask;
                pRule->prvAddr = pIoRule->uPrvIpAddr;
                pRule->pubMask = pIoRule->uPubMask;
                pRule->pubAddr = pIoRule->uPubIpAddr;

                InsertTailList(pRuleHead, &pRule->ListEntry);
            }
        }


        NdisReleaseSpinLock(pRuleLock);

        break;
    }

    NdisReleaseSpinLock(&g_AdapterListLock);

    return bOk;
}

NTSTATUS
natpDispatch(
    IN PDEVICE_OBJECT    devObject,
    IN PIRP              Irp
)
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(devObject);

    irpStack = IoGetCurrentIrpStackLocation(Irp);

    switch (irpStack->MajorFunction) {
    case IRP_MJ_CREATE:
        break;
    case IRP_MJ_CLEANUP:
        break;
    case IRP_MJ_CLOSE:
        break;
    case IRP_MJ_DEVICE_CONTROL:
    {
        PUCHAR			pBuffer;
        ULONG			InputBufferLength, OutputBufferLength, ControlCode, ReturnedSize = 0;

        pBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        InputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
        OutputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
        ControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

        switch (ControlCode) {
        case NATDRV_INIT_IOCTL:

            if (sizeof(NATDRV_IO_INIT) != InputBufferLength) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (!natbInit((NATDRV_IO_INIT*)pBuffer))
                status = STATUS_UNSUCCESSFUL;

            break;

        case NATDRV_RELEASE_IOCTL:

            if (!natbRelease())
                status = STATUS_UNSUCCESSFUL;
            break;

        case NATDRV_ADD_FW_ENTRY_IOCTL:

            if (sizeof(NATDRV_IO_FW_RULE) != InputBufferLength) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (!natbAddFirewallRule((NATDRV_IO_FW_RULE *)pBuffer)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            break;

        case NATDRV_ADD_NAT_ENTRY_IOCTL:

            if (sizeof(NATDRV_IO_NAT_ENTRY) != InputBufferLength) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (!natbAddNATEntry((NATDRV_IO_NAT_ENTRY *)pBuffer)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            break;

        default:;
        }

        if (status != STATUS_SUCCESS)
        {
            ReturnedSize = 0;
        }
        Irp->IoStatus.Information = ReturnedSize;
    }
    break;
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
