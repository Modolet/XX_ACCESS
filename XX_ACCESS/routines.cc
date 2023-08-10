#include "pch.h"

extern NTSTATUS(NTAPI *PsResumeThread)(PETHREAD Thread, PULONG PreviousCount);
extern NTSTATUS(NTAPI *PsSuspendThread)(PETHREAD Thread, PULONG PreviousSuspendCount);

extern DYNAMIC_DATA dynData;
extern LIST_ENTRY   gProtProcHead;
extern FAST_MUTEX   gProtProcMutex;

typedef struct _FreeMemoryInfo {
    WORK_QUEUE_ITEM workitem;
    HANDLE          pid;
    ULONG64         IsExecuteAddr;
    ULONG64         freeSize;

} FreeMemoryInfo, *PFreeMemoryInfo;

NTSTATUS IOPrint(PI_PRINT input, PO_PRINT result) {
    DPRINT("IOPrint:%s", input->text);
    strcpy(result->text, "SUCCESS");
    return STATUS_SUCCESS;
}

#pragma warning(disable : 4244)
NTSTATUS XXSetProtection(IN PIO_SET_PROC_PROTECTION pProtection) {
    NTSTATUS  status   = STATUS_SUCCESS;
    PEPROCESS pProcess = NULL;

    status = PsLookupProcessByProcessId((HANDLE)pProtection->pid, &pProcess);
    if (NT_SUCCESS(status)) {
        if (dynData.Protection != 0) {
            PUCHAR pValue = (PUCHAR)pProcess + dynData.Protection;

            // Win7
            if (dynData.ver <= WINVER_7_SP1) {
                if (pProtection->protection == Policy_Enable)
                    *(PULONG)pValue |= 1 << 0xB;
                else if (pProtection->protection == Policy_Disable)
                    *(PULONG)pValue &= ~(1 << 0xB);
            }
            // Win8
            else if (dynData.ver == WINVER_8) {
                if (pProtection->protection != Policy_Keep)
                    *pValue = pProtection->protection;
            }
            // Win8.1
            else if (dynData.ver >= WINVER_81) {
                // Protection
                if (pProtection->protection == Policy_Disable) {
                    *pValue = 0;
                } else if (pProtection->protection == Policy_Enable) {
                    PS_PROTECTION protBuf = {0};

                    protBuf.Flags.Signer = PsProtectedSignerWinTcb;
                    protBuf.Flags.Type   = PsProtectedTypeProtected;
                    *pValue              = protBuf.Level;
                }

                // Dynamic code
                if (pProtection->dynamicCode != Policy_Keep && dynData.EProcessFlags2 != 0) {
                    if (dynData.ver >= WINVER_10_RS3) {
                        PMITIGATION_FLAGS pFlags2   = (PMITIGATION_FLAGS)((PUCHAR)pProcess + dynData.EProcessFlags2);
                        pFlags2->DisableDynamicCode = pProtection->dynamicCode;
                    } else {
                        PEPROCESS_FLAGS2 pFlags2    = (PEPROCESS_FLAGS2)((PUCHAR)pProcess + dynData.EProcessFlags2);
                        pFlags2->DisableDynamicCode = pProtection->dynamicCode;
                    }
                }

                // Binary signature
                if (pProtection->signature != Policy_Keep) {
                    PSE_SIGNING_LEVEL pSignLevel        = (PSE_SIGNING_LEVEL)((PUCHAR)pProcess + dynData.Protection - 2);
                    PSE_SIGNING_LEVEL pSignLevelSection = (PSE_SIGNING_LEVEL)((PUCHAR)pProcess + dynData.Protection - 1);

                    if (pProtection->signature == Policy_Enable)
                        *pSignLevel = *pSignLevelSection = SE_SIGNING_LEVEL_MICROSOFT;
                    else
                        *pSignLevel = *pSignLevelSection = SE_SIGNING_LEVEL_UNCHECKED;
                }
            } else
                status = STATUS_NOT_SUPPORTED;
        } else {
            DPRINT("%s: Invalid protection flag offset\n", __FUNCTION__);
            status = STATUS_INVALID_ADDRESS;
        }
    } else
        DPRINT("%s: PsLookupProcessByProcessId failed with status 0x%X\n", __FUNCTION__, status);

    if (pProcess)
        ObDereferenceObject(pProcess);

    return status;
}
#pragma warning(default : 4244)

NTSTATUS XXProtectProcess(IN PIO_PROTECT_PROC pData) {
    NTSTATUS              status = STATUS_SUCCESS;
    PPROTECT_PROCESS_INFO info;
    PEPROCESS             process;
    status = PsLookupProcessByProcessId((HANDLE)pData->pid, &process);
    if (!NT_SUCCESS(status)) {
        DPRINT("保护进程失败");
        return status;
    }
    if (XXCheckProcessTermination(process)) {
        DPRINT("已退出的进程");
        ObDereferenceObject(process);
        status = STATUS_PROCESS_IS_TERMINATING;
        goto Exit;
    }

    for (PLIST_ENTRY listEntry = gProtProcHead.Flink; listEntry != &gProtProcHead; listEntry = listEntry->Flink) {
        PPROTECT_PROCESS_INFO minfo = (PPROTECT_PROCESS_INFO)listEntry;
        if (minfo->Peprocess == process || minfo->ProcessId == pData->pid) {
            DPRINT("已经在保护此进程");
            status = STATUS_ALREADY_COMPLETE;
            goto Exit;
        }
    }

    info = (PPROTECT_PROCESS_INFO)ExAllocatePoolWithTag(PagedPool, sizeof(PROTECT_PROCESS_INFO), XX_POOL_TAG);
    if (info) {
        info->ProcessId = pData->pid;
        info->Peprocess = process;
        ExAcquireFastMutex(&gProtProcMutex);
        ProtectProcess(info);
        InsertHeadList(&gProtProcHead, &info->listEntry);
        ExReleaseFastMutex(&gProtProcMutex);
    } else {
        status = STATUS_ALLOCATE_BUCKET;
        goto Exit;
    }

Exit:
    ObDereferenceObject(process);
    return status;
}

NTSTATUS XXUnProtectProcess(IN PIO_PROTECT_PROC pData) {
    ExAcquireFastMutex(&gProtProcMutex);
    for (PLIST_ENTRY listEntry = gProtProcHead.Flink; listEntry != &gProtProcHead; listEntry = listEntry->Flink) {
        PPROTECT_PROCESS_INFO info = (PPROTECT_PROCESS_INFO)listEntry;
        if (info->ProcessId == pData->pid) {
            UnProtectProcess(info);
            RemoveEntryList(&info->listEntry);
            ExFreePoolWithTag(info, XX_POOL_TAG);
            break;
        }
    }
    ExReleaseFastMutex(&gProtProcMutex);
    return STATUS_SUCCESS;
}