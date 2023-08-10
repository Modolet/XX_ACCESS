#include "pch.h"

PINJECT_BUFFER XXGetWow64Code(IN PVOID targetCall, IN PUNICODE_STRING pPath) {
    NTSTATUS       status  = STATUS_SUCCESS;
    PINJECT_BUFFER pBuffer = NULL;
    SIZE_T         size    = PAGE_SIZE;

    // Code
    UCHAR code[] = {
        0x68, 0x00, 0x00, 0x00, 0x00,       // push ModuleHandle            offset +1
        0x68, 0x00, 0x00, 0x00, 0x00,       // push ModuleFileName          offset +6
        0x6A, 0x00,                         // push Flags
        0x6A, 0x00,                         // push PathToFile
        0xE8, 0x00, 0x00, 0x00, 0x00,       // call LdrLoadDll              offset +15
        0xBA, 0x00, 0x00, 0x00, 0x00,       // mov edx, COMPLETE_OFFSET     offset +20
        0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0, // mov [edx], CALL_COMPLETE
        0xBA, 0x00, 0x00, 0x00, 0x00,       // mov edx, STATUS_OFFSET       offset +31
        0x89, 0x02,                         // mov [edx], eax
        0xC2, 0x04, 0x00                    // ret 4
    };

    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID *)&pBuffer, 0x00, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(status)) {
        // Copy code
        memcpy(pBuffer, code, sizeof(code));

        // Copy path
        if (pPath) {
            PUNICODE_STRING32 pUserPath = &pBuffer->path32;
            pUserPath->Length           = pPath->Length;
            pUserPath->MaximumLength    = pPath->MaximumLength;
            pUserPath->Buffer           = (ULONG)(ULONG_PTR)pBuffer->buffer;
            // Copy path
            memcpy((PVOID)pUserPath->Buffer, pPath->Buffer, pPath->Length);
            *(ULONG *)((PUCHAR)pBuffer + 6) = (ULONG)(ULONG_PTR)pUserPath;
        }

        // Fill stubs
        *(ULONG *)((PUCHAR)pBuffer + 1)  = (ULONG)(ULONG_PTR)&pBuffer->module;
        *(ULONG *)((PUCHAR)pBuffer + 15) = (ULONG)((ULONG_PTR)targetCall - ((ULONG_PTR)pBuffer + 15) - 5 + 1);
        *(ULONG *)((PUCHAR)pBuffer + 20) = (ULONG)(ULONG_PTR)&pBuffer->complete;
        *(ULONG *)((PUCHAR)pBuffer + 31) = (ULONG)(ULONG_PTR)&pBuffer->status;

        return pBuffer;
    }

    UNREFERENCED_PARAMETER(pPath);
    return NULL;
}

PINJECT_BUFFER XXGetNativeCode(IN PVOID targetCall, IN PUNICODE_STRING pPath) {
    NTSTATUS       status  = STATUS_SUCCESS;
    PINJECT_BUFFER pBuffer = NULL;
    SIZE_T         size    = PAGE_SIZE;

    // Code
    UCHAR code[] = {
        0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
        0x48, 0x31, 0xC9,                                           // xor rcx, rcx
        0x48, 0x31, 0xD2,                                           // xor rdx, rdx
        0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r8, ModuleFileName   offset +12
        0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r9, ModuleHandle     offset +28
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, LdrLoadDll      offset +32
        0xFF, 0xD0,                                                 // call rax
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, COMPLETE_OFFSET offset +44
        0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,                         // mov [rdx], CALL_COMPLETE
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, STATUS_OFFSET   offset +60
        0x48, 0x89, 0x02,                                           // mov [rdx], rax
        0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
        0xC3                                                        // ret
    };

    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID *)&pBuffer, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(status)) {
        // Copy code
        memcpy(pBuffer, code, sizeof(code));

        // Copy path
        if (pPath) {
            PUNICODE_STRING pUserPath = &pBuffer->path;
            pUserPath->Length         = 0;
            pUserPath->MaximumLength  = sizeof(pBuffer->buffer);
            pUserPath->Buffer         = pBuffer->buffer;
            RtlUnicodeStringCopy(pUserPath, pPath);
            *(ULONGLONG *)((PUCHAR)pBuffer + 12) = (ULONGLONG)pUserPath;
        }

        // Fill stubs
        *(ULONGLONG *)((PUCHAR)pBuffer + 22) = (ULONGLONG)&pBuffer->module;
        *(ULONGLONG *)((PUCHAR)pBuffer + 32) = (ULONGLONG)targetCall;
        *(ULONGLONG *)((PUCHAR)pBuffer + 44) = (ULONGLONG)&pBuffer->complete;
        *(ULONGLONG *)((PUCHAR)pBuffer + 60) = (ULONGLONG)&pBuffer->status;

        return pBuffer;
    }

    UNREFERENCED_PARAMETER(pPath);
    return NULL;
}

NTSTATUS XXApcInject(IN PINJECT_BUFFER pUserBuf, IN PEPROCESS pProcess) {
    NTSTATUS status  = STATUS_SUCCESS;
    PETHREAD pThread = NULL;
    status           = XXLookupProcessThread(pProcess, &pThread);
    if (NT_SUCCESS(status)) {
        status = XXQueueUserApc(pThread, pUserBuf->code, NULL, NULL, NULL, TRUE);
        if (NT_SUCCESS(status)) {
            LARGE_INTEGER interval = {0};
            interval.QuadPart      = -(5LL * 10 * 1000);

            for (ULONG i = 0; i < 10000; i++) {
                if (XXCheckProcessTermination(PsGetCurrentProcess()) || PsIsThreadTerminating(pThread)) {
                    status = STATUS_PROCESS_IS_TERMINATING;
                    break;
                }

                if (pUserBuf->complete == CALL_COMPLETE)
                    break;

                if (!NT_SUCCESS(status = KeDelayExecutionThread(KernelMode, FALSE, &interval)))
                    break;
            }
            if (NT_SUCCESS(status)) {
                status      = STATUS_SUCCESS;
            } else {
                DPRINT("%s: APC injection abnormal termination, status 0x%X\n", __FUNCTION__, status);
            }
        }
    }
    if (pThread)
        ObDereferenceObject(pThread);

    return status;
}

NTSTATUS IOInjectCode(IN PI_INJECT_CODE pData, OUT PO_INJECT_CODE pRet) {
    NTSTATUS  status       = STATUS_SUCCESS;
    PEPROCESS pProcess     = NULL;
    IO_SET_PROC_PROTECTION prot         = {0};

    status = PsLookupProcessByProcessId((HANDLE)pData->pid, &pProcess);
    if (NT_SUCCESS(status)) {
        KAPC_STATE apc;
        BOOLEAN isWow64 = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE;

        if (XXCheckProcessTermination(PsGetCurrentProcess())) {
            DPRINT("%s: Process %u is terminating. Abort\n", __FUNCTION__, pData->pid);
            if (pProcess)
                ObDereferenceObject(pProcess);
            
            return STATUS_PROCESS_IS_TERMINATING;
        }

        KeStackAttachProcess(pProcess, &apc);

        // If process is protected - temporarily disable protection
        if (PsIsProtectedProcess(pProcess)) {
            prot.pid         = pData->pid;
            prot.protection  = Policy_Disable;
            prot.dynamicCode = Policy_Disable;
            prot.signature   = Policy_Disable;
            XXSetProtection(&prot);
        }
        SIZE_T         size     = 0;
        PINJECT_BUFFER pUserBuf = isWow64 ? XXGetWow64Code((PVOID)pData->addr, NULL) : XXGetNativeCode((PVOID)pData->addr, NULL);
        status                  = XXApcInject(pUserBuf, pProcess);
        pRet->returnVal         = pUserBuf->status;
        ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID *)&pUserBuf, &size, MEM_RELEASE);

        if (prot.pid != 0) {
            prot.protection = Policy_Enable;
            prot.dynamicCode = Policy_Enable;
            prot.signature   = Policy_Enable;
            XXSetProtection(&prot);
        }

        KeUnstackDetachProcess(&apc);
    } else {
        DPRINT("%s: PsLookupProcessByProcessId failed with status 0x%X\n", __FUNCTION__, status);
    }
    if (pProcess)
        ObDereferenceObject(pProcess);
    return status;
}