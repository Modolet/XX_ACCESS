#pragma once
typedef struct _HANDLE_TABLE81 {
    ULONG             NextHandleNeedingPool;
    long              ExtraInfoPages;
    LONG_PTR          TableCode;
    struct _EPROCESS *QuotaProcess;
    LIST_ENTRY        HandleTableList;
    ULONG             UniqueProcessId;
    ULONG             Flags;
    EX_PUSH_LOCK      HandleContentionEvent;
    EX_PUSH_LOCK      HandleTableLock;
    // More fields here...
} HANDLE_TABLE81, *PHANDLE_TABLE81;