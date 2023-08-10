#pragma once
typedef struct _HANDLE_TABLE10 {
    ULONG        NextHandleNeedingPool;
    long         ExtraInfoPages;
    LONG_PTR     TableCode;
    PEPROCESS    QuotaProcess;
    LIST_ENTRY   HandleTableList;
    ULONG        UniqueProcessId;
    ULONG        Flags;
    EX_PUSH_LOCK HandleContentionEvent;
    EX_PUSH_LOCK HandleTableLock;
} HANDLE_TABLE10, *PHANDLE_TABLE10;