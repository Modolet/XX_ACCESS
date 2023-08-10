#pragma once
#include "pch.h"
extern ULONG        gNtProtectVirtualMemory;
extern ULONG        gNtLockVirtualMemory;
extern ULONG        gNtUnlockVirtualMemory;
extern DYNAMIC_DATA dynData;
extern ULONG        PreviousModeOffset;

NTSTATUS
NTAPI
ZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN OUT SIZE_T *NumberOfBytesToProtect,
                       IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection) {
    NTSTATUS status = STATUS_SUCCESS;

    fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)(ULONG_PTR)GetSSDTEntry(gNtProtectVirtualMemory);
    if (NtProtectVirtualMemory) {
        //
        // If previous mode is UserMode, addresses passed into NtProtectVirtualMemory must be in user-mode space
        // Switching to KernelMode allows usage of kernel-mode addresses
        //
        PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + PreviousModeOffset;
        UCHAR  prevMode  = *pPrevMode;
        PVOID  BaseCopy  = NULL;
        SIZE_T SizeCopy  = 0;
        *pPrevMode       = KernelMode;

        if (BaseAddress)
            BaseCopy = *BaseAddress;

        if (NumberOfBytesToProtect)
            SizeCopy = *NumberOfBytesToProtect;

        status = NtProtectVirtualMemory(ProcessHandle, &BaseCopy, &SizeCopy, NewAccessProtection, OldAccessProtection);

        *pPrevMode = prevMode;
    } else
        status = STATUS_NOT_FOUND;

    return status;
}

NTSTATUS NTAPI ZwLockVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG LockOption) {
    NTSTATUS status = STATUS_SUCCESS;

    fnNtLockVirtualMemory NtLockVirtualMemory = (fnNtLockVirtualMemory)(ULONG_PTR)GetSSDTEntry(gNtLockVirtualMemory);
    if (NtLockVirtualMemory) {
        //
        // If previous mode is UserMode, addresses passed into NtProtectVirtualMemory must be in user-mode space
        // Switching to KernelMode allows usage of kernel-mode addresses
        //
        PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + PreviousModeOffset;
        UCHAR  prevMode  = *pPrevMode;
        *pPrevMode       = KernelMode;

        status = NtLockVirtualMemory(ProcessHandle, BaseAddress, RegionSize, LockOption);

        *pPrevMode = prevMode;
    } else
        status = STATUS_NOT_FOUND;

    return status;
}

NTSTATUS NTAPI ZwUnlockVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG LockOption) {
    NTSTATUS status = STATUS_SUCCESS;

    fnNtUnlockVirtualMemory NtUnlockVirtualMemory = (fnNtUnlockVirtualMemory)(ULONG_PTR)GetSSDTEntry(gNtUnlockVirtualMemory);
    if (NtUnlockVirtualMemory) {
        //
        // If previous mode is UserMode, addresses passed into NtProtectVirtualMemory must be in user-mode space
        // Switching to KernelMode allows usage of kernel-mode addresses
        //
        PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + PreviousModeOffset;
        UCHAR  prevMode  = *pPrevMode;
        *pPrevMode       = KernelMode;

        status = NtUnlockVirtualMemory(ProcessHandle, BaseAddress, RegionSize, LockOption);

        *pPrevMode = prevMode;
    } else
        status = STATUS_NOT_FOUND;

    return status;
}