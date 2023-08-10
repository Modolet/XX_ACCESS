#include "pch.h"
#include "ssdt.h"

extern ULONG gNtCreateThdExIndex;

#define MemoryMappedFilenameInformation (2)
#define THREAD_INFO_SIZE                (0x6E4)
static ULONG THREAD_INFO_SECTIONS[] = {0x78,  0x7C,  0xC3,  0xC5,  0x220, 0x228, 0x233, 0x234, 0x240, 0x250,
                                       0x28C, 0x290, 0x2DC, 0x2E0, 0x5D8, 0x618, 0x680, 0x6A8, 0x6BC, THREAD_INFO_SIZE};

ULONG PreviousModeOffset = 0;

extern NTSTATUS(NTAPI *PsSuspendThread)(PETHREAD Thread, PULONG PreviousSuspendCount);
extern NTSTATUS(NTAPI *PsResumeThread)(PETHREAD Thread, PULONG PreviousCount);

typedef NTSTATUS(NTAPI *fnNtCreateThreadEx)(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes,
                                            IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter,
                                            IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit,
                                            IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);

NTSTATUS
NTAPI
ZwCreateThreadEx(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle,
                 IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits,
                 IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList) {
    NTSTATUS status = STATUS_SUCCESS;

    fnNtCreateThreadEx NtCreateThreadEx = (fnNtCreateThreadEx)(ULONG_PTR)GetSSDTEntry(gNtCreateThdExIndex);
    if (NtCreateThreadEx) {
        //
        // If previous mode is UserMode, addresses passed into ZwCreateThreadEx must be in user-mode space
        // Switching to KernelMode allows usage of kernel-mode addresses
        //
        PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + PreviousModeOffset;
        UCHAR  prevMode  = *pPrevMode;
        *pPrevMode       = KernelMode;

        status = NtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags,
                                  StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, AttributeList);

        *pPrevMode = prevMode;
    } else
        status = STATUS_NOT_FOUND;

    return status;
}

BOOL ProbeUserAddress(PVOID addr, SIZE_T size, ULONG alignment) {
    if (size == 0) {
        return TRUE;
    }

    ULONG_PTR current = (ULONG_PTR)addr;
    if (((ULONG_PTR)addr & (alignment - 1)) != 0) {
        return FALSE;
    }

    ULONG_PTR last = current + size - 1;
    if ((last < current) || (last >= MmUserProbeAddress)) {
        return FALSE;
    }

    return TRUE;
}

static VOID AdjustRelativePointers(PBYTE buffer, PBYTE target, SIZE_T size) {
    if (size < sizeof(PVOID)) {
        return;
    }

    for (SIZE_T i = 0; i <= size - sizeof(PVOID); i += sizeof(ULONG)) {
        PVOID *ptr    = (PVOID *)(buffer + i);
        SIZE_T offset = (PBYTE)*ptr - buffer;

        if (offset < size) {
            *ptr = target + offset;
            i += sizeof(ULONG);
        }
    }
}

KPROCESSOR_MODE KeSetPreviousMode(KPROCESSOR_MODE mode) {
    KPROCESSOR_MODE old                                                    = ExGetPreviousMode();
    *(KPROCESSOR_MODE *)((PBYTE)KeGetCurrentThread() + PreviousModeOffset) = mode;
    return old;
}

BOOL SafeCopy(PVOID dest, PVOID src, SIZE_T size) {
    SIZE_T returnSize = 0;
    if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), src, PsGetCurrentProcess(), dest, size, KernelMode, &returnSize)) &&
        returnSize == size) {
        return TRUE;
    }

    return FALSE;
}

/*** Process ***/
NTSTATUS XXIONTOpenProcess(PIONTOPENPROCESS_ARGS args) {
    CLIENT_ID clientId = {0};

    if (!ProbeUserAddress(args->ClientId, sizeof(CLIENT_ID), sizeof(LONG)) ||
        !SafeCopy(&clientId, args->ClientId, sizeof(clientId)) ||
        !ProbeUserAddress(args->ProcessHandle, sizeof(HANDLE), sizeof(LONG))) {

        return STATUS_ACCESS_VIOLATION;
    }

    NTSTATUS status = STATUS_SUCCESS;
    if ((ULONGLONG)clientId.UniqueProcess == 0x31C0) {
        return status;
    }
    if (clientId.UniqueProcess == 0 || (ULONGLONG)clientId.UniqueProcess % 4 != 0) {
        return STATUS_INVALID_HANDLE;
    }
    if (clientId.UniqueThread) {
        PETHREAD  thread  = 0;
        PEPROCESS process = 0;

        if (NT_SUCCESS(status = PsLookupProcessThreadByCid(&clientId, &process, &thread))) {
            HANDLE processHandle = EncodeHandle(PsGetProcessId(process));
            if (!SafeCopy(args->ProcessHandle, &processHandle, sizeof(processHandle))) {
                status = STATUS_ACCESS_VIOLATION;
            }

            ObDereferenceObject(thread);
            ObDereferenceObject(process);
        }
    } else {
        PEPROCESS process = 0;

        if (NT_SUCCESS(status = PsLookupProcessByProcessId(clientId.UniqueProcess, &process))) {
            HANDLE processHandle = EncodeHandle(clientId.UniqueProcess);
            if (!SafeCopy(args->ProcessHandle, &processHandle, sizeof(processHandle))) {
                status = STATUS_ACCESS_VIOLATION;
            }

            ObDereferenceObject(process);
        }
    }

    return status;
}

NTSTATUS XXIONTSuspendProcess(PIONTSUSPENDPROCESS_ARGS args) {
    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        status = PsSuspendProcess(process);
        ObDereferenceObject(process);
    }

    return status;
}

NTSTATUS XXIONTResumeProcess(PIONTRESUMEPROCESS_ARGS args) {
    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        status = PsResumeProcess(process);
        ObDereferenceObject(process);
    }

    return status;
}

NTSTATUS XXIONTQuerySystemInformationEx(PIONTQUERYSYSTEMINFORMATIONEX_ARGS args) {
    switch (args->SystemInformationClass) {
    case SystemSupportedProcessArchitectures:
        if (args->InputBuffer && args->InputBufferLength == sizeof(HANDLE)) {
            HANDLE processHandle = 0;
            if (!ProbeUserAddress(args->InputBuffer, args->InputBufferLength, sizeof(LONG)) ||
                !ProbeUserAddress(args->SystemInformation, args->SystemInformationLength, sizeof(LONG)) ||
                (args->ReturnLength && !ProbeUserAddress(args->ReturnLength, sizeof(ULONG), sizeof(LONG))) ||
                !SafeCopy(&processHandle, args->InputBuffer, sizeof(processHandle))) {

                return STATUS_ACCESS_VIOLATION;
            }

            PEPROCESS process = 0;
            NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(processHandle), &process);
            if (NT_SUCCESS(status)) {
                processHandle = NtCurrentProcess();

                PVOID systemInformation = 0;
                ULONG returnLength      = 0;

                if (args->SystemInformation && args->SystemInformationLength) {
                    systemInformation = ExAllocatePool(NonPagedPool, args->SystemInformationLength);
                    if (!systemInformation) {
                        ObDereferenceObject(process);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                }

                KeAttachProcess((PKPROCESS)process);
                KeEnterCriticalRegion();
                KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

                status = NtQuerySystemInformationEx(args->SystemInformationClass, &processHandle, args->InputBufferLength,
                                                    systemInformation, args->SystemInformationLength, &returnLength);

                KeSetPreviousMode(previousMode);
                KeLeaveCriticalRegion();
                KeDetachProcess();

                ObDereferenceObject(process);

                if (NT_SUCCESS(status) && systemInformation) {
                    if (!SafeCopy(args->SystemInformation, systemInformation, returnLength)) {
                        status = STATUS_ACCESS_VIOLATION;
                    }

                    ExFreePool(systemInformation);
                }

                if (args->ReturnLength) {
                    if (!SafeCopy(args->ReturnLength, &returnLength, sizeof(returnLength))) {
                        status = STATUS_ACCESS_VIOLATION;
                    }
                }
            }

            return status;
        }

        break;
    }

    return NtQuerySystemInformationEx(args->SystemInformationClass, args->InputBuffer, args->InputBufferLength,
                                      args->SystemInformation, args->SystemInformationLength, args->ReturnLength);
}

NTSTATUS XXIONTQueryInformationProcess(PIONTQUERYINFORMATIONPROCESS_ARGS args) {
    if (args->ProcessInformation) {
        if (!ProbeUserAddress(args->ProcessInformation, args->ProcessInformationLength, sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    if (args->ReturnLength) {
        if (!ProbeUserAddress(args->ReturnLength, sizeof(ULONG), sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        PVOID processInformation = 0;
        ULONG returnLength       = 0;

        if (args->ProcessInformation && args->ProcessInformationLength) {
            processInformation = ExAllocatePool(NonPagedPool, args->ProcessInformationLength);
            if (!processInformation) {
                ObDereferenceObject(process);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        KeAttachProcess((PKPROCESS)process);
        KeEnterCriticalRegion();
        KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

        status = NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)args->ProcessInformationClass,
                                           processInformation, args->ProcessInformationLength, &returnLength);

        KeSetPreviousMode(previousMode);
        KeLeaveCriticalRegion();
        KeDetachProcess();

        ObDereferenceObject(process);

        if (NT_SUCCESS(status) && processInformation) {
            AdjustRelativePointers((PBYTE)processInformation, (PBYTE)args->ProcessInformation, returnLength);

            if (!SafeCopy(args->ProcessInformation, processInformation, returnLength)) {
                status = STATUS_ACCESS_VIOLATION;
            }

            ExFreePool(processInformation);
        }

        if (args->ReturnLength) {
            if (!SafeCopy(args->ReturnLength, &returnLength, sizeof(returnLength))) {
                status = STATUS_ACCESS_VIOLATION;
            }
        }
    }

    return status;
}

NTSTATUS XXIONTSetInformationProcess(PIONTSETINFORMATIONPROCESS_ARGS args) {
    if (!args->ProcessInformation || !args->ProcessInformationLength) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ProbeUserAddress(args->ProcessInformation, args->ProcessInformationLength, sizeof(BYTE))) {
        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        PVOID processInformation = ExAllocatePool(NonPagedPool, args->ProcessInformationLength);
        if (processInformation) {
            if (!SafeCopy(processInformation, args->ProcessInformation, args->ProcessInformationLength)) {
                status = STATUS_ACCESS_VIOLATION;
            }

            if (NT_SUCCESS(status)) {
                KeAttachProcess((PKPROCESS)process);
                KeEnterCriticalRegion();
                KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

                status = NtSetInformationProcess(NtCurrentProcess(), args->ProcessInformationClass, processInformation,
                                                 args->ProcessInformationLength);

                KeSetPreviousMode(previousMode);
                KeLeaveCriticalRegion();
                KeDetachProcess();
            }

            ExFreePool(processInformation);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }

        ObDereferenceObject(process);
    }

    return status;
}

NTSTATUS XXIONTFlushInstructionCache(PIONTFLUSHINSTRUCTIONCACHE_ARGS args) {
    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        KeAttachProcess((PKPROCESS)process);

        status = ZwFlushInstructionCache(NtCurrentProcess(), args->BaseAddress, args->NumberOfBytesToFlush);

        KeDetachProcess();

        ObDereferenceObject(process);
    }

    return status;
}

/*** Memory ***/
NTSTATUS XXIONTAllocateVirtualMemory(PIONTALLOCATEVIRTUALMEMORY_ARGS args) {
    PVOID  baseAddress = 0;
    SIZE_T regionSize  = 0;

    if (!ProbeUserAddress(args->BaseAddress, sizeof(PVOID), sizeof(LONG)) ||
        !ProbeUserAddress(args->RegionSize, sizeof(SIZE_T), sizeof(LONG)) ||
        !SafeCopy(&baseAddress, args->BaseAddress, sizeof(baseAddress)) ||
        !SafeCopy(&regionSize, args->RegionSize, sizeof(regionSize))) {

        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        KeAttachProcess((PKPROCESS)process);
        KeEnterCriticalRegion();
        KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

        status = NtAllocateVirtualMemory(NtCurrentProcess(), &baseAddress, args->ZeroBits, &regionSize, args->AllocationType,
                                         args->Protect);

        KeSetPreviousMode(previousMode);
        KeLeaveCriticalRegion();
        KeDetachProcess();

        ObDereferenceObject(process);

        if (!SafeCopy(args->BaseAddress, &baseAddress, sizeof(baseAddress)) ||
            !SafeCopy(args->RegionSize, &regionSize, sizeof(regionSize))) {

            status = STATUS_ACCESS_VIOLATION;
        }
    }

    return status;
}

NTSTATUS XXIONTFlushVirtualMemory(PIONTFLUSHVIRTUALMEMORY_ARGS args) {
    PVOID           baseAddress = 0;
    SIZE_T          regionSize  = 0;
    IO_STATUS_BLOCK ioStatus    = {0};
    if (!ProbeUserAddress(args->BaseAddress, sizeof(PVOID), sizeof(LONG)) ||
        !ProbeUserAddress(args->RegionSize, sizeof(SIZE_T), sizeof(LONG)) ||
        !ProbeUserAddress(args->IoStatus, sizeof(IO_STATUS_BLOCK), sizeof(LONG)) ||
        !SafeCopy(&baseAddress, args->BaseAddress, sizeof(baseAddress)) ||
        !SafeCopy(&regionSize, args->RegionSize, sizeof(regionSize)) || !SafeCopy(&ioStatus, args->IoStatus, sizeof(ioStatus))) {

        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        KeAttachProcess((PKPROCESS)process);

        status = ZwFlushVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, &ioStatus);

        KeDetachProcess();

        ObDereferenceObject(process);

        if (!SafeCopy(args->BaseAddress, &baseAddress, sizeof(baseAddress)) ||
            !SafeCopy(args->RegionSize, &regionSize, sizeof(regionSize)) ||
            !SafeCopy(args->IoStatus, &ioStatus, sizeof(ioStatus))) {

            status = STATUS_ACCESS_VIOLATION;
        }
    }

    return status;
}

NTSTATUS XXIONTFreeVirtualMemory(PIONTFREEVIRTUALMEMORY_ARGS args) {
    PVOID  baseAddress = 0;
    SIZE_T regionSize  = 0;
    if (!ProbeUserAddress(args->BaseAddress, sizeof(PVOID), sizeof(LONG)) ||
        !ProbeUserAddress(args->RegionSize, sizeof(SIZE_T), sizeof(LONG)) ||
        !SafeCopy(&baseAddress, args->BaseAddress, sizeof(baseAddress)) ||
        !SafeCopy(&regionSize, args->RegionSize, sizeof(regionSize))) {

        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        KeAttachProcess((PKPROCESS)process);
        KeEnterCriticalRegion();
        KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

        status = NtFreeVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, args->FreeType);

        KeSetPreviousMode(previousMode);
        KeLeaveCriticalRegion();
        KeDetachProcess();

        ObDereferenceObject(process);

        if (!SafeCopy(args->BaseAddress, &baseAddress, sizeof(baseAddress)) ||
            !SafeCopy(args->RegionSize, &regionSize, sizeof(regionSize))) {

            status = STATUS_ACCESS_VIOLATION;
        }
    }

    return status;
}

NTSTATUS XXIONTLockVirtualMemory(PIONTLOCKVIRTUALMEMORY_ARGS args) {
    PVOID  baseAddress = 0;
    SIZE_T regionSize  = 0;
    if (!ProbeUserAddress(args->BaseAddress, sizeof(PVOID), sizeof(LONG)) ||
        !ProbeUserAddress(args->RegionSize, sizeof(SIZE_T), sizeof(LONG)) ||
        !SafeCopy(&baseAddress, args->BaseAddress, sizeof(baseAddress)) ||
        !SafeCopy(&regionSize, args->RegionSize, sizeof(regionSize))) {

        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        KeAttachProcess((PKPROCESS)process);

        status = ZwLockVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, args->LockOption);

        KeDetachProcess();

        ObDereferenceObject(process);

        if (!SafeCopy(args->BaseAddress, &baseAddress, sizeof(baseAddress)) ||
            !SafeCopy(args->RegionSize, &regionSize, sizeof(regionSize))) {

            status = STATUS_ACCESS_VIOLATION;
        }
    }

    return status;
}

NTSTATUS XXIONTUnlockVirtualMemory(PIONTUNLOCKVIRTUALMEMORY_ARGS args) {
    PVOID  baseAddress = 0;
    SIZE_T regionSize  = 0;
    if (!ProbeUserAddress(args->BaseAddress, sizeof(PVOID), sizeof(LONG)) ||
        !ProbeUserAddress(args->RegionSize, sizeof(SIZE_T), sizeof(LONG)) ||
        !SafeCopy(&baseAddress, args->BaseAddress, sizeof(baseAddress)) ||
        !SafeCopy(&regionSize, args->RegionSize, sizeof(regionSize))) {

        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        KeAttachProcess((PKPROCESS)process);

        status = ZwUnlockVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, args->LockOption);

        KeDetachProcess();

        ObDereferenceObject(process);

        if (!SafeCopy(args->BaseAddress, &baseAddress, sizeof(baseAddress)) ||
            !SafeCopy(args->RegionSize, &regionSize, sizeof(regionSize))) {

            status = STATUS_ACCESS_VIOLATION;
        }
    }

    return status;
}

NTSTATUS XXIONTProtectVirtualMemory(PIONTPROTECTVIRTUALMEMORY_ARGS args) {
    PVOID  baseAddress = 0;
    SIZE_T regionSize  = 0;
    if (!ProbeUserAddress(args->BaseAddress, sizeof(PVOID), sizeof(LONG)) ||
        !ProbeUserAddress(args->RegionSize, sizeof(SIZE_T), sizeof(LONG)) ||
        !ProbeUserAddress(args->OldAccessProtection, sizeof(ULONG), sizeof(LONG)) ||
        !SafeCopy(&baseAddress, args->BaseAddress, sizeof(baseAddress)) ||
        !SafeCopy(&regionSize, args->RegionSize, sizeof(regionSize))) {

        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        ULONG oldAccessProtection = 0;

        KeAttachProcess((PKPROCESS)process);

        status = ZwProtectVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, args->NewAccessProtection,
                                        &oldAccessProtection);

        KeDetachProcess();

        ObDereferenceObject(process);

        if (!SafeCopy(args->BaseAddress, &baseAddress, sizeof(baseAddress)) ||
            !SafeCopy(args->RegionSize, &regionSize, sizeof(regionSize)) ||
            !SafeCopy(args->OldAccessProtection, &oldAccessProtection, sizeof(oldAccessProtection))) {

            status = STATUS_ACCESS_VIOLATION;
        }
    }

    return status;
}

NTSTATUS XXIONTReadVirtualMemory(PIONTREADVIRTUALMEMORY_ARGS args) {
    if (((PBYTE)args->BaseAddress + args->NumberOfBytesToRead < (PBYTE)args->BaseAddress) ||
        ((PBYTE)args->Buffer + args->NumberOfBytesToRead < (PBYTE)args->Buffer) ||
        ((PVOID)((PBYTE)args->BaseAddress + args->NumberOfBytesToRead) > MM_HIGHEST_USER_ADDRESS) ||
        ((PVOID)((PBYTE)args->Buffer + args->NumberOfBytesToRead) > MM_HIGHEST_USER_ADDRESS)) {

        return STATUS_ACCESS_VIOLATION;
    }

    if (args->NumberOfBytesRead) {
        if (!ProbeUserAddress(args->NumberOfBytesRead, sizeof(SIZE_T), sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        if (args->NumberOfBytesToRead) {
            SIZE_T numberOfBytesRead = 0;

            status = MmCopyVirtualMemory(process, args->BaseAddress, PsGetCurrentProcess(), args->Buffer,
                                         args->NumberOfBytesToRead, ExGetPreviousMode(), &numberOfBytesRead);

            if (args->NumberOfBytesRead) {
                if (!SafeCopy(args->NumberOfBytesRead, &numberOfBytesRead, sizeof(numberOfBytesRead))) {
                    status = STATUS_ACCESS_VIOLATION;
                }
            }
        }

        ObDereferenceObject(process);
    }

    return status;
}

NTSTATUS XXIONTWriteVirtualMemory(PIONTWRITEVIRTUALMEMORY_ARGS args) {
    if (((PBYTE)args->BaseAddress + args->NumberOfBytesToWrite < (PBYTE)args->BaseAddress) ||
        ((PBYTE)args->Buffer + args->NumberOfBytesToWrite < (PBYTE)args->Buffer) ||
        ((PVOID)((PBYTE)args->BaseAddress + args->NumberOfBytesToWrite) > MM_HIGHEST_USER_ADDRESS) ||
        ((PVOID)((PBYTE)args->Buffer + args->NumberOfBytesToWrite) > MM_HIGHEST_USER_ADDRESS)) {

        return STATUS_ACCESS_VIOLATION;
    }

    if (args->NumberOfBytesWritten) {
        if (!ProbeUserAddress(args->NumberOfBytesWritten, sizeof(SIZE_T), sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        if (args->NumberOfBytesToWrite) {
            SIZE_T numberOfBytesWritten = 0;

            status = MmCopyVirtualMemory(PsGetCurrentProcess(), args->Buffer, process, args->BaseAddress,
                                         args->NumberOfBytesToWrite, ExGetPreviousMode(), &numberOfBytesWritten);

            if (args->NumberOfBytesWritten) {
                if (!SafeCopy(args->NumberOfBytesWritten, &numberOfBytesWritten, sizeof(numberOfBytesWritten))) {
                    status = STATUS_ACCESS_VIOLATION;
                }
            }
        }

        ObDereferenceObject(process);
    }

    return status;
}

NTSTATUS XXIONTQueryVirtualMemory(PIONTQUERYVIRTUALMEMORY_ARGS args) {
    if (args->MemoryInformation) {
        if (!ProbeUserAddress(args->MemoryInformation, args->MemoryInformationLength, sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    if (args->ReturnLength) {
        if (!ProbeUserAddress(args->ReturnLength, sizeof(SIZE_T), sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    PEPROCESS process = 0;
    NTSTATUS  status  = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (NT_SUCCESS(status)) {
        PVOID  memoryInformation = 0;
        SIZE_T returnLength      = 0;

        if (args->MemoryInformation && args->MemoryInformationLength) {
            memoryInformation = ExAllocatePool(NonPagedPool, args->MemoryInformationLength);
            if (!memoryInformation) {
                ObDereferenceObject(process);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        KeAttachProcess((PKPROCESS)process);

        status = ZwQueryVirtualMemory(NtCurrentProcess(), args->BaseAddress, args->MemoryInformationClass, memoryInformation,
                                      args->MemoryInformationLength, &returnLength);

        KeDetachProcess();

        ObDereferenceObject(process);

        if (NT_SUCCESS(status) && memoryInformation) {
            if (args->MemoryInformationClass == MemoryMappedFilenameInformation) {
                AdjustRelativePointers((PBYTE)memoryInformation, (PBYTE)args->MemoryInformation, returnLength);
            }

            if (!SafeCopy(args->MemoryInformation, memoryInformation, returnLength)) {
                status = STATUS_ACCESS_VIOLATION;
            }

            ExFreePool(memoryInformation);
        }

        if (args->ReturnLength) {
            if (!SafeCopy(args->ReturnLength, &returnLength, sizeof(returnLength))) {
                status = STATUS_ACCESS_VIOLATION;
            }
        }
    }

    return status;
}

/*** Thread ***/
NTSTATUS XXIONTOpenThread(PIONTOPENTHREAD_ARGS args) {
    CLIENT_ID clientId = {0};
    if (!ProbeUserAddress(args->ClientId, sizeof(CLIENT_ID), sizeof(LONG)) ||
        !ProbeUserAddress(args->ThreadHandle, sizeof(HANDLE), sizeof(LONG)) ||
        !SafeCopy(&clientId, args->ClientId, sizeof(clientId))) {

        return STATUS_ACCESS_VIOLATION;
    }

    NTSTATUS status = STATUS_SUCCESS;
    if (clientId.UniqueProcess) {
        PETHREAD  thread  = 0;
        PEPROCESS process = 0;

        if (NT_SUCCESS(status = PsLookupProcessThreadByCid(&clientId, &process, &thread))) {
            HANDLE threadHandle = EncodeHandle(PsGetThreadId(thread));
            if (!SafeCopy(args->ThreadHandle, &threadHandle, sizeof(threadHandle))) {
                status = STATUS_ACCESS_VIOLATION;
            }

            ObDereferenceObject(thread);
            ObDereferenceObject(process);
        }
    } else {
        PETHREAD thread = 0;

        if (NT_SUCCESS(status = PsLookupThreadByThreadId(clientId.UniqueThread, &thread))) {
            HANDLE threadHandle = EncodeHandle(clientId.UniqueThread);
            if (!SafeCopy(args->ThreadHandle, &threadHandle, sizeof(threadHandle))) {
                status = STATUS_ACCESS_VIOLATION;
            }

            ObDereferenceObject(thread);
        }
    }

    return status;
}

NTSTATUS XXIONTCreateThreadEx(PIONTCREATETHREADEX_ARGS args) {
    NTSTATUS                 status   = STATUS_SUCCESS;
    HANDLE                   hThread  = NULL;
    PEPROCESS                process  = NULL;
    THREAD_BASIC_INFORMATION info     = {0};
    DWORD                    info_len = 0;

    status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
    if (!NT_SUCCESS(status))
        return status;
    KeAttachProcess((PKPROCESS)process);
    KeEnterCriticalRegion();

    KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

    status = ZwCreateThreadEx(&hThread, args->DesiredAccess, (POBJECT_ATTRIBUTES)args->ObjectAttributes, ZwCurrentProcess(),
                              args->lpStartAddress, args->lpParameter, args->Flags, args->StackZeroBits, args->SizeOfStackCommit,
                              args->SizeOfStackReserve, NULL);

    KeSetPreviousMode(previousMode);
    if (!NT_SUCCESS(status)) {
        goto exit;
    }

    status = ZwQueryInformationThread(hThread, ThreadBasicInformation, &info, sizeof(info), &info_len);

    if (!NT_SUCCESS(status)) {
        goto exit;
    }
    hThread = EncodeHandle(&info.ClientId.UniqueThread);

exit:
    KeLeaveCriticalRegion();
    KeDetachProcess();
    ObfDereferenceObject(process);
    SafeCopy(args->hThread, &hThread, sizeof(hThread));
    return status;
}

NTSTATUS XXIONTQueryInformationThread(PIONTQUERYINFORMATIONTHREAD_ARGS args) {
    if (args->ThreadInformation) {
        if (!ProbeUserAddress(args->ThreadInformation, args->ThreadInformationLength, sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    if (args->ReturnLength) {
        if (!ProbeUserAddress(args->ReturnLength, sizeof(ULONG), sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    PETHREAD thread = 0;
    NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
    if (NT_SUCCESS(status)) {
        // This is an unsafe way to get thread info without a handle, APC, or manual implementation of ETHREAD structure
        KeEnterGuardedRegion();

        BYTE info[THREAD_INFO_SIZE] = {0};
        memcpy(info, PsGetCurrentThread(), THREAD_INFO_SIZE);

        for (ULONG i = 0; i < LENGTH(THREAD_INFO_SECTIONS); i += 2) {
            ULONG start = THREAD_INFO_SECTIONS[i];
            ULONG end   = THREAD_INFO_SECTIONS[i + 1];
            memcpy((PBYTE)PsGetCurrentThread() + start, (PBYTE)thread + start, end - start);
        }

        status = ZwQueryInformationThread(NtCurrentThread(), args->ThreadInformationClass, args->ThreadInformation,
                                          args->ThreadInformationLength, args->ReturnLength);

        // Manually copy TEB if requested
        if (NT_SUCCESS(status) && args->ThreadInformationClass == ThreadBasicInformation && args->ThreadInformation &&
            args->ThreadInformationLength) {
            PVOID tebBaseAddress = PsGetThreadTeb(thread);
            if (!SafeCopy(&((PTHREAD_BASIC_INFORMATION)args->ThreadInformation)->TebBaseAddress, &tebBaseAddress,
                          sizeof(tebBaseAddress))) {
                status = STATUS_ACCESS_VIOLATION;
            }
        }

        for (ULONG i = 0; i < LENGTH(THREAD_INFO_SECTIONS); i += 2) {
            ULONG start = THREAD_INFO_SECTIONS[i];
            ULONG end   = THREAD_INFO_SECTIONS[i + 1];
            memcpy((PBYTE)PsGetCurrentThread() + start, (PBYTE)info + start, end - start);
        }

        KeLeaveGuardedRegion();

        ObDereferenceObject(thread);
    }

    return status;
}

NTSTATUS XXIONTSetInformationThread(PIONTSETINFORMATIONTHREAD_ARGS args) {
    if (args->ThreadInformation && args->ThreadInformationLength) {
        if (!ProbeUserAddress(args->ThreadInformation, args->ThreadInformationLength, sizeof(BYTE))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    PETHREAD thread = 0;
    NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
    if (NT_SUCCESS(status)) {
        KeEnterGuardedRegion();

        switch (args->ThreadInformationClass) {
        case ThreadZeroTlsCell:
            // Don't mess with current thread's TEB
            status = STATUS_NOT_IMPLEMENTED;
            break;
        case ThreadIdealProcessor: {
            if (!args->ThreadInformation) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (args->ThreadInformationLength != sizeof(ULONG)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            ULONG idealProcessor = 0;
            if (!SafeCopy(&idealProcessor, args->ThreadInformation, sizeof(idealProcessor))) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            status = KeSetIdealProcessorThread(thread, (UCHAR)idealProcessor);

            break;
        }
        default:
            // Same story as NtQueryInformationThread
            // if (NT_SUCCESS(status = PsSuspendThread(thread, 0))) {
            //     BYTE info[THREAD_INFO_SIZE] = {0};
            //     memcpy(info, PsGetCurrentThread(), THREAD_INFO_SIZE);
            //
            //     for (ULONG i = 0; i < LENGTH(THREAD_INFO_SECTIONS); i += 2) {
            //      ULONG start = THREAD_INFO_SECTIONS[i];
            //      ULONG end   = THREAD_INFO_SECTIONS[i + 1];
            //      memcpy((PBYTE)PsGetCurrentThread() + start, (PBYTE)thread + start, end - start);
            //  }
            //
            //     status = ZwSetInformationThread(NtCurrentThread(), args->ThreadInformationClass, args->ThreadInformation,
            //                                     args->ThreadInformationLength);
            //
            //     for (ULONG i = 0; i < LENGTH(THREAD_INFO_SECTIONS); i += 2) {
            //      ULONG start = THREAD_INFO_SECTIONS[i];
            //      ULONG end   = THREAD_INFO_SECTIONS[i + 1];
            //      ULONG len   = end - start;
            //
            //      memcpy((PBYTE)thread + start, (PBYTE)PsGetCurrentThread() + start, len);
            //      memcpy((PBYTE)PsGetCurrentThread() + start, (PBYTE)info + start, len);
            //  }
            //
            //     PsResumeThread(thread, 0);
            // }

            break;
        }

        KeLeaveGuardedRegion();

        ObDereferenceObject(thread);
    }

    return status;
}

NTSTATUS XXIONTGetContextThread(PIONTGETCONTEXTTHREAD_ARGS args) {
    PETHREAD thread = 0;
    NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
    if (NT_SUCCESS(status)) {
        status = PsGetContextThread(thread, args->Context, ExGetPreviousMode());
        ObDereferenceObject(thread);
    }

    return status;
}

NTSTATUS XXIONTSetContextThread(PIONTSETCONTEXTTHREAD_ARGS args) {
    PETHREAD thread = 0;
    NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
    if (NT_SUCCESS(status)) {
        status = PsSetContextThread(thread, args->Context, ExGetPreviousMode());
        ObDereferenceObject(thread);
    }

    return status;
}

NTSTATUS XXIONTResumeThread(PIONTRESUMETHREAD_ARGS args) {
    if (args->SuspendCount) {
        if (!ProbeUserAddress(args->SuspendCount, sizeof(ULONG), sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    PETHREAD thread = 0;
    NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
    if (NT_SUCCESS(status)) {
        ULONG suspendCount = 0;

        // status = PsResumeThread(thread, &suspendCount);
        status = STATUS_NOT_SUPPORTED;
        ObDereferenceObject(thread);

        if (args->SuspendCount) {
            if (!SafeCopy(args->SuspendCount, &suspendCount, sizeof(suspendCount))) {
                status = STATUS_ACCESS_VIOLATION;
            }
        }
    }

    return status;
}

NTSTATUS XXIONTSuspendThread(PIONTSUSPENDTHREAD_ARGS args) {
    if (args->PreviousSuspendCount) {
        if (!ProbeUserAddress(args->PreviousSuspendCount, sizeof(ULONG), sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    PETHREAD thread = 0;
    NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
    if (NT_SUCCESS(status)) {
        ULONG previousSuspendCount = 0;

        // status = PsSuspendThread(thread, &previousSuspendCount);
        status = STATUS_NOT_SUPPORTED;
        ObDereferenceObject(thread);

        if (args->PreviousSuspendCount) {
            if (!SafeCopy(args->PreviousSuspendCount, &previousSuspendCount, sizeof(previousSuspendCount))) {
                status = STATUS_ACCESS_VIOLATION;
            }
        }
    }

    return status;
}

/*** Sync ***/
NTSTATUS XXIONTWaitForSingleObject(PIONTWAITFORSINGLEOBJECT_ARGS args) {
    HANDLE    id      = DecodeHandle(args->Handle);
    HANDLE    handle  = 0;
    PETHREAD  thread  = 0;
    PEPROCESS process = 0;
    NTSTATUS  status  = STATUS_SUCCESS;

    // ACs don't care about synchronize rights - CBA to not use a handle
    if (NT_SUCCESS(status = PsLookupProcessByProcessId(id, &process))) {
        status = ObOpenObjectByPointer(process, 0, 0, SYNCHRONIZE, *PsProcessType, KernelMode, &handle);
        ObDereferenceObject(process);
    } else if (NT_SUCCESS(status = PsLookupThreadByThreadId(id, &thread))) {
        status = ObOpenObjectByPointer(thread, 0, 0, SYNCHRONIZE, *PsThreadType, KernelMode, &handle);
        ObDereferenceObject(thread);
    }

    if (NT_SUCCESS(status)) {
        status = NtWaitForSingleObject(handle, args->Alertable, args->Timeout);
        NtClose(handle);
    }

    return status;
}

NTSTATUS XXIONTDuplicateObject(PIONTDUPLICATEOBJECT_ARGS args) {
    NTSTATUS    status              = STATUS_SUCCESS;
    HANDLE      SourceProcessHandle = args->SourceProcessHandle;
    HANDLE      SourceHandle        = args->SourceHandle;
    HANDLE      TargetProcessHandle = args->TargetProcessHandle;
    PHANDLE     TargetHandle        = args->TargetHandle;
    ACCESS_MASK DesiredAccess       = args->DesiredAccess;
    ULONG       HandleAttributes    = args->HandleAttributes;
    ULONG       Options             = args->Options;

    HANDLE            zwTarProcHandle = TargetProcessHandle;
    CLIENT_ID         client;
    OBJECT_ATTRIBUTES ObjAttr;
    memset(&ObjAttr, 0, sizeof(OBJECT_ATTRIBUTES));
    client.UniqueProcess = DecodeHandle(zwTarProcHandle);
    client.UniqueThread  = 0;
    status               = ZwOpenProcess(&zwTarProcHandle, PROCESS_ALL_ACCESS, &ObjAttr, &client);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwDuplicateObject(SourceProcessHandle, SourceHandle, zwTarProcHandle, TargetHandle, DesiredAccess, HandleAttributes,
                               Options);
    ZwClose(zwTarProcHandle);
    return status;
}

NTSTATUS XXIOIsWow64Process(PIOISWOW64PROCESS_ARGS args) {
    if (!ProbeUserAddress(args->Wow64Process, 4, 4)) {
        return STATUS_ACCESS_VIOLATION;
    }
    PEPROCESS pProcess;
    NTSTATUS  status = PsLookupProcessByProcessId(DecodeHandle(args->hProcess), &pProcess);
    if (NT_SUCCESS(status)) {
        *args->Wow64Process = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE;
    }
    if (pProcess)
        ObDereferenceObject(pProcess);
    return status;
}
