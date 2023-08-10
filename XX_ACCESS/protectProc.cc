#include "pch.h"
extern LIST_ENTRY   gProtProcHead;
extern FAST_MUTEX   gProtProcMutex;
extern DYNAMIC_DATA dynData;

NTSTATUS ProtectProcess(PPROTECT_PROCESS_INFO info) {
    NTSTATUS  status = STATUS_SUCCESS;
    ULONG64   table  = 0;
    EXHANDLE  exHandle;
    // PEPROCESS pExplorerEProcess = NULL;

    status = XXGetPspCidTable(&table);
    if (!NT_SUCCESS(status)) {
        DPRINT("! %s %x: ��ȡʧ��: PspCidTable!!", __FUNCTION__, status);
        goto Exit0;
    }
    // PLIST_ENTRY pListEntry   = (PLIST_ENTRY)((ULONG64)info->Peprocess + dynData.ActiveProcessLinks);
    // info->blank              = pListEntry->Blink;
    // info->flank              = pListEntry->Flink;
    // pListEntry->Blink->Flink = pListEntry->Flink;
    // pListEntry->Flink->Blink = pListEntry->Blink;
    // pListEntry->Blink        = pListEntry;
    // pListEntry->Flink        = pListEntry;

    exHandle.Value            = (ULONG_PTR)info->ProcessId;
    ULONG64 pHandleTableEntry = (ULONG64)ExpLookupHandleTableEntry((PHANDLE_TABLE)table, exHandle);
    if (!pHandleTableEntry) {
        goto Exit0;
    }
    info->PHandleTableEntry       = (PHANDLE_TABLE_ENTRY)pHandleTableEntry;
    info->ObjectHeader            = *(ULONG64 *)pHandleTableEntry;
    *(ULONG64 *)pHandleTableEntry = 0;

    *(ULONG64 *)((PUCHAR)info->Peprocess + dynData.UniqueProcessId) = 0;

    UCHAR *imageFileName = PsGetProcessImageFileName(info->Peprocess);
    if (imageFileName) {
        RtlCopyMemory(info->imageFileName, imageFileName, 15);
        RtlZeroMemory(imageFileName, 15);
    }

    // status = XXLookupProcessByName("explorer.exe", &pExplorerEProcess);
    // if (!NT_SUCCESS(status)) {
    //     DPRINT("��ȡexplorer.exe EPROCESSʧ��");
    //     goto Exit0;
    // }
    // PLIST_ENTRY pThreadListHead = (PLIST_ENTRY)((ULONG64)info->Peprocess + dynData.EProcessThreadListHead);
    // for (PLIST_ENTRY peThreadEntry = pThreadListHead->Flink; peThreadEntry != pThreadListHead;
    //      peThreadEntry             = peThreadEntry->Flink) {
    //     PVOID     pThread       = (PVOID)((ULONG64)peThreadEntry - dynData.EThreadThreadListHead);
    //     *(PEPROCESS *)((ULONG64)pThread + dynData.KThreadProcess) = pExplorerEProcess;
    // }

    DPRINT("�������̳ɹ�:%s %d", PsGetProcessImageFileName(info->Peprocess), info->ProcessId);
    return STATUS_SUCCESS;

Exit0:
    DPRINT("��������ʧ��:%s %d", PsGetProcessImageFileName(info->Peprocess), info->ProcessId);
    return status;
}

NTSTATUS UnProtectProcess(PPROTECT_PROCESS_INFO info) {
    NTSTATUS status = STATUS_SUCCESS;
    // if (info->flank && info->blank) {
    //     PLIST_ENTRY pListEntry = (PLIST_ENTRY)((ULONG64)info->Peprocess + dynData.ActiveProcessLinks);
    //     info->flank->Blink     = pListEntry;
    //     info->blank->Flink     = pListEntry;
    //     pListEntry->Blink      = info->blank;
    //     pListEntry->Flink      = info->flank;
    // }
    if (info->PHandleTableEntry) {
        *(ULONG64 *)info->PHandleTableEntry = info->ObjectHeader;
    }
    *(ULONG64 *)((PUCHAR)info->Peprocess + dynData.UniqueProcessId) = info->ProcessId;
    UCHAR *imageFileName                                            = PsGetProcessImageFileName(info->Peprocess);
    if (imageFileName) {
        RtlCopyMemory(imageFileName, info->imageFileName, 15);
    }

    // PLIST_ENTRY pThreadListHead = (PLIST_ENTRY)((ULONG64)info->Peprocess + dynData.EProcessThreadListHead);
    // for (PLIST_ENTRY peThreadEntry = pThreadListHead->Flink; peThreadEntry != pThreadListHead;
    //      peThreadEntry             = peThreadEntry->Flink) {
    //     PVOID     pThread       = (PVOID)((ULONG64)peThreadEntry - dynData.EThreadThreadListHead);
    //     *(PEPROCESS *)((ULONG64)pThread + dynData.KThreadProcess) = info->Peprocess;
    // }

    DPRINT("ȡ����������:%s %d", PsGetProcessImageFileName(info->Peprocess), info->ProcessId);
    return status;
}

VOID CleanProtectProcess() {
    ExAcquireFastMutex(&gProtProcMutex);
    for (PLIST_ENTRY listEntry = gProtProcHead.Flink; listEntry != &gProtProcHead;) {
        PPROTECT_PROCESS_INFO info = (PPROTECT_PROCESS_INFO)listEntry;
        listEntry                  = listEntry->Flink;
        UnProtectProcess(info);
        RemoveEntryList(&info->listEntry);
        ExFreePoolWithTag(info, XX_POOL_TAG);
        break;
    }
    ExReleaseFastMutex(&gProtProcMutex);
}
