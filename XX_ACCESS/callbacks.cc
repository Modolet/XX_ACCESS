#include "pch.h"

extern LIST_ENTRY gProtProcHead;
extern FAST_MUTEX gProtProcMutex;

VOID XXProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UCHAR *imageFileName = PsGetProcessImageFileName(Process);
    if (CreateInfo == NULL) {
        ExAcquireFastMutex(&gProtProcMutex);
        for (PLIST_ENTRY listEntry = gProtProcHead.Flink; listEntry != &gProtProcHead; listEntry = listEntry->Flink) {
            PPROTECT_PROCESS_INFO info = (PPROTECT_PROCESS_INFO)listEntry;
            if (info->Peprocess == Process) {
                DPRINT("受保护进程退出:%d %s", ProcessId, imageFileName);
                UnProtectProcess(info);
                RemoveEntryList(&info->listEntry);
                ExFreePoolWithTag(info, XX_POOL_TAG);
                break;
            }
        }
        ExReleaseFastMutex(&gProtProcMutex);
    }
}

OB_PREOP_CALLBACK_STATUS pobLowerPreOperationCallBack(_In_ PVOID                            RegistrationContext,
                                                      _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType == *PsThreadType) {
        return OB_PREOP_SUCCESS;
    }
    PEPROCESS process        = (PEPROCESS)OperationInformation->Object;
    PEPROCESS currentProcess = PsGetCurrentProcess();
    ExAcquireFastMutex(&gProtProcMutex);
    for (PLIST_ENTRY listEntry = gProtProcHead.Flink; listEntry != &gProtProcHead; listEntry = listEntry->Flink) {
        PPROTECT_PROCESS_INFO info = (PPROTECT_PROCESS_INFO)listEntry;
        if (info->Peprocess == process && currentProcess != process) {
            // OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess    = 0;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
            // OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
            break;
        } else if (info->Peprocess == currentProcess) {
            // OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess    = 0x1fffff;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;
            // OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0x1fffff;
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0x1fffff;
            break;
        }
    }

    ExReleaseFastMutex(&gProtProcMutex);
    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS pobUpperPreOperationCallBack(_In_ PVOID                            RegistrationContext,
                                                      _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType == *PsThreadType) {
        return OB_PREOP_SUCCESS;
    }
    PEPROCESS process        = (PEPROCESS)OperationInformation->Object;
    PEPROCESS currentProcess = PsGetCurrentProcess();
    ExAcquireFastMutex(&gProtProcMutex);
    for (PLIST_ENTRY listEntry = gProtProcHead.Flink; listEntry != &gProtProcHead; listEntry = listEntry->Flink) {
        PPROTECT_PROCESS_INFO info = (PPROTECT_PROCESS_INFO)listEntry;
        if (info->Peprocess == process && currentProcess != process) {
            // OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess    = 0;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
            // OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
            break;
        } else if (info->Peprocess == currentProcess) {
            // OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess    = 0x1fffff;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;
            // OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0x1fffff;
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0x1fffff;
            break;
        }
    }
    ExReleaseFastMutex(&gProtProcMutex);
    return OB_PREOP_SUCCESS;
}