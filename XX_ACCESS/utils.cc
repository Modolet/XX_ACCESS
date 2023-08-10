#include "pch.h"

extern DYNAMIC_DATA dynData;

PVOID                            g_KernelBase = NULL;
ULONG                            g_KernelSize = 0;
PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT       = NULL;

NTSTATUS XXSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID *base, IN ULONG_PTR size,
                         OUT PVOID *ppFound) {
    ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
    if (ppFound == NULL || pattern == NULL || base == NULL)
        return STATUS_INVALID_PARAMETER;

    for (ULONG_PTR i = 0; i < size - len; i++) {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++) {
            if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j]) {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE) {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

VOID KernelSleep(ULONG64 ms, BOOLEAN alert) {
    LARGE_INTEGER inTime;
    inTime.QuadPart = ms * -10000;
    KeDelayExecutionThread(KernelMode, alert, &inTime);
}

NTSTATUS NTAPI NtGetNextThread(__in HANDLE ProcessHandle, __in HANDLE ThreadHandle, __in ACCESS_MASK DesiredAccess,
                               __in ULONG HandleAttributes, __in ULONG Flags, __out PHANDLE NewThreadHandle) {

    typedef NTSTATUS(NTAPI * ZwGetNextThreadProc)(__in HANDLE ProcessHandle, __in HANDLE ThreadHandle,
                                                  __in ACCESS_MASK DesiredAccess, __in ULONG HandleAttributes, __in ULONG Flags,
                                                  __out PHANDLE NewThreadHandle);

    static ZwGetNextThreadProc ZwGetNextThreadFunc = NULL;
    if (!ZwGetNextThreadFunc) {
        UNICODE_STRING unName = {0};
        RtlInitUnicodeString(&unName, L"ZwGetNextThread");
        ZwGetNextThreadFunc = (ZwGetNextThreadProc)MmGetSystemRoutineAddress(&unName);
        if (!ZwGetNextThreadFunc) {
            UNICODE_STRING uunName = {0};
            RtlInitUnicodeString(&uunName, L"ZwGetNotificationResourceManager");
            PUCHAR ZwGetNotificationResourceManagerAddr = (PUCHAR)MmGetSystemRoutineAddress(&uunName);
            ZwGetNotificationResourceManagerAddr -= 0x50;
            for (int i = 0; i < 0x30; i++) {
                if (ZwGetNotificationResourceManagerAddr[i] == 0x48 && ZwGetNotificationResourceManagerAddr[i + 1] == 0x8B &&
                    ZwGetNotificationResourceManagerAddr[i + 2] == 0xC4) {
                    ZwGetNextThreadFunc = (ZwGetNextThreadProc)(ZwGetNotificationResourceManagerAddr + i);
                    break;
                }
            }
        }
    }

    if (ZwGetNextThreadFunc) {
        return ZwGetNextThreadFunc(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
    }

    return STATUS_UNSUCCESSFUL;
}

PETHREAD NtGetProcessMainThread(PEPROCESS Process) {
    PETHREAD ethread = NULL;

    KAPC_STATE kApcState = {0};

    KeStackAttachProcess(Process, &kApcState);

    HANDLE hThread = NULL;

    NTSTATUS status =
        NtGetNextThread(NtCurrentProcess(), NULL, THREAD_ALL_ACCESS, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, &hThread);

    if (NT_SUCCESS(status)) {

        status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID *)&ethread, NULL);
        NtClose(hThread);

        if (!NT_SUCCESS(status)) {
            ethread = NULL;
        }
    }

    KeUnstackDetachProcess(&kApcState);
    return ethread;
}

BOOLEAN XXCheckProcessTermination(PEPROCESS pProcess) {
    LARGE_INTEGER zeroTime = {0};
    return KeWaitForSingleObject(pProcess, Executive, KernelMode, FALSE, &zeroTime) == STATUS_WAIT_0;
}

BOOLEAN XXSkipThread(IN PETHREAD pThread, IN BOOLEAN isWow64) {
    PUCHAR pTeb64 = (PUCHAR)PsGetThreadTeb(pThread);
    if (!pTeb64)
        return TRUE;

    // Skip GUI treads. APC to GUI thread causes ZwUserGetMessage to fail
    // TEB64 + 0x78  = Win32ThreadInfo
    if (*(PULONG64)(pTeb64 + 0x78) != 0)
        return TRUE;

    // Skip threads with no ActivationContext
    // Skip threads with no TLS pointer
    if (isWow64) {
        PUCHAR pTeb32 = pTeb64 + 0x2000;

        // TEB32 + 0x1A8 = ActivationContextStackPointer
        if (*(PULONG32)(pTeb32 + 0x1A8) == 0)
            return TRUE;

        // TEB64 + 0x2C = ThreadLocalStoragePointer
        if (*(PULONG32)(pTeb32 + 0x2C) == 0)
            return TRUE;
    } else {
        // TEB64 + 0x2C8 = ActivationContextStackPointer
        if (*(PULONG64)(pTeb64 + 0x2C8) == 0)
            return TRUE;

        // TEB64 + 0x58 = ThreadLocalStoragePointer
        if (*(PULONG64)(pTeb64 + 0x58) == 0)
            return TRUE;
    }

    return FALSE;
}

NTSTATUS XXLookupProcessThread(IN PEPROCESS pProcess, OUT PETHREAD *ppThread) {
    NTSTATUS             status = STATUS_SUCCESS;
    HANDLE               pid    = PsGetProcessId(pProcess);
    PVOID                pBuf   = ExAllocatePoolWithTag(NonPagedPool, 1024 * 1024, XX_POOL_TAG);
    PSYSTEM_PROCESS_INFO pInfo  = (PSYSTEM_PROCESS_INFO)pBuf;

    ASSERT(ppThread != NULL);
    if (ppThread == NULL)
        return STATUS_INVALID_PARAMETER;

    if (!pInfo) {
        DPRINT("%s: Failed to allocate memory for process list\n", __FUNCTION__);
        return STATUS_NO_MEMORY;
    }

    // Get the process thread list
    status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(pBuf, XX_POOL_TAG);
        return status;
    }

    // Find target thread
    if (NT_SUCCESS(status)) {
        status = STATUS_NOT_FOUND;
        for (;;) {
            if (pInfo->UniqueProcessId == pid) {
                status = STATUS_SUCCESS;
                break;
            } else if (pInfo->NextEntryOffset)
                pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
            else
                break;
        }
    }

    BOOLEAN wow64 = PsGetProcessWow64Process(pProcess) != NULL;

    // Reference target thread
    if (NT_SUCCESS(status)) {
        status = STATUS_NOT_FOUND;

        // Get first thread
        for (ULONG i = 0; i < pInfo->NumberOfThreads; i++) {
            // Skip current thread
            if (/*pInfo->Threads[i].WaitReason == Suspended ||
                 pInfo->Threads[i].ThreadState == 5 ||*/
                pInfo->Threads[i].ClientId.UniqueThread == PsGetCurrentThreadId()) {
                continue;
            }

            status = PsLookupThreadByThreadId(pInfo->Threads[i].ClientId.UniqueThread, ppThread);

            // Skip specific threads
            if (*ppThread && XXSkipThread(*ppThread, wow64)) {
                ObDereferenceObject(*ppThread);
                *ppThread = NULL;
                continue;
            }

            break;
        }
    } else
        DPRINT("%s: Failed to locate process\n", __FUNCTION__);

    if (pBuf)
        ExFreePoolWithTag(pBuf, XX_POOL_TAG);

    // No suitable thread
    if (!*ppThread)
        status = STATUS_NOT_FOUND;

    return status;
}

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(IN PHANDLE_TABLE GHandleTable, IN EXHANDLE tHandle) {
#define __CODE_PUB_PRE(_VER)                                                                                                     \
    PHANDLE_TABLE##_VER HandleTable = (PHANDLE_TABLE##_VER)GHandleTable;                                                         \
    ULONG_PTR           TableCode   = HandleTable->TableCode & 3;                                                                \
    if (tHandle.Value >= HandleTable->NextHandleNeedingPool)                                                                     \
        return NULL;                                                                                                             \
    tHandle.Value &= 0xFFFFFFFFFFFFFFFC

#define __CODE8_PUB                                                                                                              \
    if (TableCode != 0) {                                                                                                        \
        if (TableCode == 1) {                                                                                                    \
            return (PHANDLE_TABLE_ENTRY)(*(ULONG_PTR *)(HandleTable->TableCode + 8 * (tHandle.Value >> 10) - 1) +                \
                                         4 * (tHandle.Value & 0x3FF));                                                           \
        } else {                                                                                                                 \
            ULONG_PTR tmp = tHandle.Value >> 10;                                                                                 \
            return (PHANDLE_TABLE_ENTRY)(*(ULONG_PTR *)(*(ULONG_PTR *)(HandleTable->TableCode + 8 * (tHandle.Value >> 19) - 2) + \
                                                        8 * (tmp & 0x1FF)) +                                                     \
                                         4 * (tHandle.Value & 0x3FF));                                                           \
        }                                                                                                                        \
    } else {                                                                                                                     \
        return (PHANDLE_TABLE_ENTRY)(HandleTable->TableCode + 4 * tHandle.Value);                                                \
    }\

    if (dynData.ver >= WINVER_10) {
        __CODE_PUB_PRE(10);
        if (TableCode != 0) {
            if (TableCode == 1) {
                return (PHANDLE_TABLE_ENTRY)(*(ULONG_PTR *)(HandleTable->TableCode + 8 * (tHandle.Value >> 11) - 1) +
                                             4 * (tHandle.Value & 0x7FC));
            } else {
                ULONG_PTR tmp = tHandle.Value >> 11;
                return (
                    PHANDLE_TABLE_ENTRY)(*(ULONG_PTR *)(*(ULONG_PTR *)(HandleTable->TableCode + 8 * (tHandle.Value >> 21) - 2) +
                                                        8 * (tmp & 0x3FF)) +
                                         4 * (tHandle.Value & 0x7FC));
            }
        } else {
            return (PHANDLE_TABLE_ENTRY)(HandleTable->TableCode + 4 * tHandle.Value);
        }
    } else if (dynData.ver >= WINVER_81) {
        __CODE_PUB_PRE(81);
        __CODE8_PUB;
    } else if (dynData.ver >= WINVER_8) {
        __CODE_PUB_PRE(8);
        __CODE8_PUB;
    } else {
        __CODE_PUB_PRE(7);
        ULONG_PTR Diff = HandleTable->TableCode - TableCode;

        if (TableCode != 0) {
            if (TableCode == 1) {
                return (PHANDLE_TABLE_ENTRY)(*(ULONG_PTR *)(Diff + ((tHandle.Value - tHandle.Value & 0x7FC) >> 9)) +
                                             4 * (tHandle.Value & 0x7FC));
            } else {
                ULONG_PTR tmp = (tHandle.Value - tHandle.Value & 0x7FC) >> 9;
                return (PHANDLE_TABLE_ENTRY)(*(ULONG_PTR *)(*(ULONG_PTR *)(Diff + ((tHandle.Value - tmp - tmp & 0xFFF) >> 10)) +
                                                            (tmp & 0xFFF)) +
                                             4 * (tHandle.Value & 0x7FC));
            }
        } else {
            return (PHANDLE_TABLE_ENTRY)(Diff + 4 * tHandle.Value);
        }
    }

#undef __CODE
#undef __CODE8_PUB
}

NTSTATUS XXGetPspCidTable(PULONG64 tableAddr) {
    // 获取 PsLookupProcessByProcessId 地址
    UNICODE_STRING uc_funcName;
    RtlInitUnicodeString(&uc_funcName, L"PsLookupProcessByProcessId");
    ULONG64 ul_funcAddr = (ULONG64)MmGetSystemRoutineAddress(&uc_funcName);
    if (ul_funcAddr == 0) {
        // DbgPrint("[LYSM] MmGetSystemRoutineAddress error.\n");
        return STATUS_NOT_FOUND;
    }
    // DbgPrint("[LYSM] PsLookupProcessByProcessId:%p\n", ul_funcAddr);

    // 前 40 字节有 call（PspReferenceCidTableEntry）
    ULONG64 ul_entry = 0;
    for (INT i = 0; i < 40; i++) {
        if (*(PUCHAR)(ul_funcAddr + i) == 0xe8) {
            ul_entry = ul_funcAddr + i;
            break;
        }
    }
    if (ul_entry != 0) {
        // 解析 call 地址
        INT i_callCode = *(INT *)(ul_entry + 1);
        // DbgPrint("[LYSM] i_callCode:%X\n", i_callCode);
        ULONG64 ul_callJmp = ul_entry + i_callCode + 5;
        // DbgPrint("[LYSM] ul_callJmp:%p\n", ul_callJmp);
        //  来到 call（PspReferenceCidTableEntry） 内找 PspCidTable
        for (INT i = 0; i < 40; i++) {
            if (*(PUCHAR)(ul_callJmp + i) == 0x48 && *(PUCHAR)(ul_callJmp + i + 1) == 0x8b &&
                *(PUCHAR)(ul_callJmp + i + 2) == 0x05) {
                // 解析 mov 地址
                INT i_movCode = *(INT *)(ul_callJmp + i + 3);
                // DbgPrint("[LYSM] i_movCode:%X\n", i_movCode);
                ULONG64 ul_movJmp = ul_callJmp + i + i_movCode + 7;
                // DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);
                //  得到 PspCidTable
                *tableAddr = ul_movJmp;
                return STATUS_SUCCESS;
            }
        }
    }

    // 前 40字节没有 call
    else {
        // 直接在 PsLookupProcessByProcessId 找 PspCidTable
        for (INT i = 0; i < 70; i++) {
            if (*(PUCHAR)(ul_funcAddr + i) == 0x49 && *(PUCHAR)(ul_funcAddr + i + 1) == 0x8b &&
                *(PUCHAR)(ul_funcAddr + i + 2) == 0xdc && *(PUCHAR)(ul_funcAddr + i + 3) == 0x48 &&
                *(PUCHAR)(ul_funcAddr + i + 4) == 0x8b && *(PUCHAR)(ul_funcAddr + i + 5) == 0xd1 &&
                *(PUCHAR)(ul_funcAddr + i + 6) == 0x48 && *(PUCHAR)(ul_funcAddr + i + 7) == 0x8b) {
                // 解析 mov 地址
                INT i_movCode = *(INT *)(ul_funcAddr + i + 6 + 3);
                // DbgPrint("[LYSM] i_movCode:%X\n", i_movCode);
                ULONG64 ul_movJmp = ul_funcAddr + i + 6 + i_movCode + 7;
                // DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);
                //  得到 PspCidTable
                *tableAddr = ul_movJmp;
                return STATUS_SUCCESS;
            }
        }
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS XXLookupProcessByName(IN PCHAR pcProcessName, OUT PEPROCESS *pEprocess) {
    PEPROCESS   pCurEprocess       = NULL;
    PEPROCESS   pNextEprocess      = NULL; // 做为一个标记，表示循环了一圈
    PLIST_ENTRY pListActiveProcess = NULL;
    ULONG       uLoopNum           = 0; // 查找的循环次数

    if (!ARGUMENT_PRESENT(pcProcessName) || !ARGUMENT_PRESENT(pEprocess)) {
        return STATUS_INVALID_PARAMETER;
    }

    // 遍历链表查询
    pCurEprocess  = PsGetCurrentProcess();
    pNextEprocess = pCurEprocess;

    __try {
        while (TRUE) {
            // TODO.做想做的事吧...
            const char *lpszAttackProName = (const char *)PsGetProcessImageFileName(pCurEprocess);
            if (lpszAttackProName && strlen(lpszAttackProName) == strlen(pcProcessName)) {
                if (0 == _stricmp(lpszAttackProName, pcProcessName)) {
                    *pEprocess = pCurEprocess;
                    return STATUS_SUCCESS;
                }
            }
            // 出口
            if (uLoopNum >= 1 && pNextEprocess == pCurEprocess) {
                *pEprocess = 0x00000000;
                return STATUS_NOT_FOUND;
            }

            pListActiveProcess =
                (PLIST_ENTRY)((ULONG64)pCurEprocess + dynData.ActiveProcessLinks); // 注意大括号，不用大括号会出错的
            pCurEprocess = (PEPROCESS)((ULONG64)pListActiveProcess->Flink -
                                       dynData.ActiveProcessLinks); // pCurEprocess临时表示了前一个Active process
            uLoopNum++;                                             // 循环次数+1
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DPRINT("[LookupProcessByName]--execption:%08x--end", GetExceptionCode());
        *pEprocess = 0x00000000;
        return STATUS_NOT_FOUND;
    }
}

PVOID GetKernelBase(OUT PULONG pSize) {
    NTSTATUS             status   = STATUS_SUCCESS;
    ULONG                bytes    = 0;
    PRTL_PROCESS_MODULES pMods    = NULL;
    PVOID                checkPtr = NULL;
    UNICODE_STRING       routineName;

    // Already found
    if (g_KernelBase != NULL) {
        if (pSize)
            *pSize = g_KernelSize;
        return g_KernelBase;
    }

    RtlUnicodeStringInit(&routineName, L"NtOpenFile");

    checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (checkPtr == NULL)
        return NULL;

    // Protect from UserMode AV
    status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0) {
        DPRINT("%s: Invalid SystemModuleInformation size\n", __FUNCTION__);
        return NULL;
    }

    pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, XX_POOL_TAG);
    RtlZeroMemory(pMods, bytes);

    status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

    if (NT_SUCCESS(status)) {
        PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

        for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
            // System routine is inside module
            if (checkPtr >= pMod[i].ImageBase && checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize)) {
                g_KernelBase = pMod[i].ImageBase;
                g_KernelSize = pMod[i].ImageSize;
                if (pSize)
                    *pSize = g_KernelSize;
                break;
            }
        }
    }

    if (pMods)
        ExFreePoolWithTag(pMods, XX_POOL_TAG);

    return g_KernelBase;
}

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase() {
    PUCHAR ntosBase = (PUCHAR)GetKernelBase(NULL);

    // Already found
    if (g_SSDT != NULL)
        return g_SSDT;

    if (!ntosBase)
        return NULL;

    PIMAGE_NT_HEADERS     pHdr      = RtlImageNtHeader(ntosBase);
    PIMAGE_SECTION_HEADER pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++) {
        // Non-paged, non-discardable, readable sections
        // Probably still not fool-proof enough...
        if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED && pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            !(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) && (*(PULONG)pSec->Name != 'TINI') &&
            (*(PULONG)pSec->Name != 'EGAP')) {
            PVOID pFound = NULL;

            // KiSystemServiceRepeat pattern
            UCHAR    pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
            NTSTATUS status    = XXSearchPattern(pattern, 0xCC, sizeof(pattern) - 1, ntosBase + pSec->VirtualAddress,
                                                 pSec->Misc.VirtualSize, &pFound);
            if (NT_SUCCESS(status)) {
                g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
                // DPRINT( "BlackBone: %s: KeSystemServiceDescriptorTable = 0x%p\n", __FUNCTION__, g_SSDT );
                return g_SSDT;
            }
        }
    }

    return NULL;
}

PVOID GetSSDTEntry(IN ULONG index) {
    ULONG                            size  = 0;
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = GetSSDTBase();
    PVOID                            pBase = GetKernelBase(&size);

    if (pSSDT && pBase) {
        // Index range check
        if (index > pSSDT->NumberOfServices)
            return NULL;

        return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
    }

    return NULL;
}