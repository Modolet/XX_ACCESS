#pragma once
typedef struct _HANDLE_TABLE8 {
    ULONG             NextHandleNeedingPool;
    long              ExtraInfoPages;
    ULONG_PTR         TableCode;
    struct _EPROCESS *QuotaProcess;
    LIST_ENTRY        HandleTableList;
    ULONG             UniqueProcessId;
    ULONG             Flags;
    EX_PUSH_LOCK      HandleContentionEvent;
    EX_PUSH_LOCK      HandleTableLock;
    // More fields here...
} HANDLE_TABLE8, *PHANDLE_TABLE8;