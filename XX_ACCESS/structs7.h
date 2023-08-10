#pragma once
typedef struct _HANDLE_TABLE7 {
    ULONG_PTR                        TableCode;
    struct _EPROCESS                *QuotaProcess;
    HANDLE                           UniqueProcessId;
    void                            *HandleLock;
    struct _LIST_ENTRY               HandleTableList;
    EX_PUSH_LOCK                     HandleContentionEvent;
    struct _HANDLE_TRACE_DEBUG_INFO *DebugInfo;
    int                              ExtraInfoPages;
    ULONG                            Flags;
    ULONG                            FirstFreeHandle;
    struct _HANDLE_TABLE_ENTRY      *LastFreeHandleEntry;
    ULONG                            HandleCount;
    ULONG                            NextHandleNeedingPool;
    // More fields here...
} HANDLE_TABLE7, *PHANDLE_TABLE7;

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)
(
    IN HANDLE ProcessHandle,
    IN PVOID* BaseAddress,
    IN SIZE_T* NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection
    );

typedef NTSTATUS (NTAPI* fnNtLockVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG LockOption);
typedef NTSTATUS (NTAPI* fnNtUnlockVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG LockOption);