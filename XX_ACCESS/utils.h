#pragma once

NTSTATUS XXSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID *base, IN ULONG_PTR size,
                         OUT PVOID *ppFound);

VOID KernelSleep(ULONG64 ms, BOOLEAN alert);

NTSTATUS NTAPI NtGetNextThread(__in HANDLE ProcessHandle, __in HANDLE ThreadHandle, __in ACCESS_MASK DesiredAccess,
                               __in ULONG HandleAttributes, __in ULONG Flags, __out PHANDLE NewThreadHandle);

PETHREAD NtGetProcessMainThread(PEPROCESS Process);

BOOLEAN XXCheckProcessTermination(PEPROCESS pProcess);

NTSTATUS XXLookupProcessThread(IN PEPROCESS pProcess, OUT PETHREAD *ppThread);

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(IN PHANDLE_TABLE HandleTable, IN EXHANDLE tHandle);

NTSTATUS XXGetPspCidTable(PULONG64 tableAddr);

NTSTATUS XXLookupProcessByName(IN PCHAR pcProcessName, OUT PEPROCESS *pEprocess);

PVOID GetKernelBase(OUT PULONG pSize);

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase();

PVOID GetSSDTEntry(IN ULONG index);