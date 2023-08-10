#pragma once

#define CALL_COMPLETE 0xC0371E7E

typedef struct _INJECT_BUFFER {
    UCHAR code[0x200];
    union {
        UNICODE_STRING   path;
        UNICODE_STRING32 path32;
    };

    wchar_t  buffer[488];
    PVOID    module;
    ULONG    complete;
    ULONG64 status;
} INJECT_BUFFER, *PINJECT_BUFFER;

PINJECT_BUFFER XXGetNativeCode(IN PVOID targetCall, IN PUNICODE_STRING pPath = NULL);
NTSTATUS       IOInjectCode(IN PI_INJECT_CODE pData, OUT PO_INJECT_CODE pRet);
