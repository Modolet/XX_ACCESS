#pragma once

#define DBG_NAME "XXDRV"
#define RELPRINT
#define DBGPRINT(format, ...)                                                                                                    \
    do {                                                                                                                         \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] - ", DBG_NAME);                                                \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format##"\n", __VA_ARGS__);                                          \
    } while (FALSE)

#ifdef DBG
#define DPRINT DBGPRINT
#else
#ifdef RELPRINT
#define DPRINT DBGPRINT
#else
#define DPRINT(...)
#endif
#endif

typedef enum _WinVer {
    WINVER_7       = 0x0610,
    WINVER_7_SP1   = 0x0611,
    WINVER_8       = 0x0620,
    WINVER_81      = 0x0630,
    WINVER_10      = 0x0A00,
    WINVER_10_RS1  = 0x0A01, // Anniversary update
    WINVER_10_RS2  = 0x0A02, // Creators update
    WINVER_10_RS3  = 0x0A03, // Fall creators update
    WINVER_10_RS4  = 0x0A04, // Spring creators update
    WINVER_10_RS5  = 0x0A05, // October 2018 update
    WINVER_10_19H1 = 0x0A06, // May 2019 update 19H1
    WINVER_10_19H2 = 0x0A07, // November 2019 update 19H2
    WINVER_10_20H1 = 0x0A08, // April 2020 update 20H1
} WinVer;

typedef struct _DYNAMIC_DATA {
    WinVer  ver;          // OS version
    ULONG   buildNo;      // OS build revision
    BOOLEAN correctBuild; // OS kernel build number is correct and supported

    ULONG Protection;             // EPROCESS::Protection
    ULONG EProcessFlags2;         // EPROCESS::Flags2
    ULONG UniqueProcessId;        // EPROCESS::UniqueProcessId
    ULONG ActiveProcessLinks;     // EPROCESS::ActiveProcessLinks
    ULONG EProcessThreadListHead; // EPROCESS::EProcessThreadListHead
    ULONG EThreadThreadListHead;
    // ULONG NtProtectIndex;         // NtProtectVirtualMemory SSDT index
    ULONG KThreadProcess;

    // ULONG NtCreateThdExIndex;
} DYNAMIC_DATA, *PDYNAMIC_DATA;

typedef struct _PROTECT_PROCESS_INFO {
    LIST_ENTRY          listEntry;
    ULONG               ProcessId;
    PEPROCESS           Peprocess;
    PLIST_ENTRY         flank;
    PLIST_ENTRY         blank;
    PHANDLE_TABLE_ENTRY PHandleTableEntry;
    ULONG64             ObjectHeader;
    UCHAR               imageFileName[15];
} PROTECT_PROCESS_INFO, *PPROTECT_PROCESS_INFO;

typedef struct _LDR_DATA {
    struct _LIST_ENTRY     InLoadOrderLinks;
    struct _LIST_ENTRY     InMemoryOrderLinks;
    struct _LIST_ENTRY     InInitializationOrderLinks;
    VOID                  *DllBase;
    VOID                  *EntryPoint;
    ULONG32                SizeOfImage;
    UINT8                  _PADDING0_[0x4];
    struct _UNICODE_STRING FullDllName;
    struct _UNICODE_STRING BaseDllName;
    ULONG32                Flags;
} LDR_DATA, *PLDR_DATA;
