#pragma once

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    UCHAR      Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         TlsIndex;
    LIST_ENTRY     HashLinks;
    ULONG          TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    UCHAR         InheritedAddressSpace;
    UCHAR         ReadImageFileExecOptions;
    UCHAR         BeingDebugged;
    UCHAR         BitField;
    PVOID         Mutant;
    PVOID         ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID         ProcessParameters;
    PVOID         SubSystemData;
    PVOID         ProcessHeap;
    PVOID         FastPebLock;
    PVOID         AtlThunkSListPtr;
    PVOID         IFEOKey;
    PVOID         CrossProcessFlags;
    PVOID         KernelCallbackTable;
    ULONG         SystemReserved;
    ULONG         AtlThunkSListPtr32;
    PVOID         ApiSetMap;
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA32 {
    ULONG        Length;
    UCHAR        Initialized;
    ULONG        SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32     InLoadOrderLinks;
    LIST_ENTRY32     InMemoryOrderLinks;
    LIST_ENTRY32     InInitializationOrderLinks;
    ULONG            DllBase;
    ULONG            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG            Flags;
    USHORT           LoadCount;
    USHORT           TlsIndex;
    LIST_ENTRY32     HashLinks;
    ULONG            TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32 {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    ULONG CrossProcessFlags;
    ULONG UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
} PEB32, *PPEB32;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    KPRIORITY     Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    KWAIT_REASON  WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG                     NextEntryOffset;
    ULONG                     NumberOfThreads;
    LARGE_INTEGER             WorkingSetPrivateSize;
    ULONG                     HardFaultCount;
    ULONG                     NumberOfThreadsHighWatermark;
    ULONGLONG                 CycleTime;
    LARGE_INTEGER             CreateTime;
    LARGE_INTEGER             UserTime;
    LARGE_INTEGER             KernelTime;
    UNICODE_STRING            ImageName;
    KPRIORITY                 BasePriority;
    HANDLE                    UniqueProcessId;
    HANDLE                    InheritedFromUniqueProcessId;
    ULONG                     HandleCount;
    ULONG                     SessionId;
    ULONG_PTR                 UniqueProcessKey;
    SIZE_T                    PeakVirtualSize;
    SIZE_T                    VirtualSize;
    ULONG                     PageFaultCount;
    SIZE_T                    PeakWorkingSetSize;
    SIZE_T                    WorkingSetSize;
    SIZE_T                    QuotaPeakPagedPoolUsage;
    SIZE_T                    QuotaPagedPoolUsage;
    SIZE_T                    QuotaPeakNonPagedPoolUsage;
    SIZE_T                    QuotaNonPagedPoolUsage;
    SIZE_T                    PagefileUsage;
    SIZE_T                    PeakPagefileUsage;
    SIZE_T                    PrivatePageCount;
    LARGE_INTEGER             ReadOperationCount;
    LARGE_INTEGER             WriteOperationCount;
    LARGE_INTEGER             OtherOperationCount;
    LARGE_INTEGER             ReadTransferCount;
    LARGE_INTEGER             WriteTransferCount;
    LARGE_INTEGER             OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef union _PS_PROTECTION {
    UCHAR Level;
    struct {
        int Type   : 3;
        int Audit  : 1;
        int Signer : 4;
    } Flags;
} PS_PROTECTION, *PPS_PROTECTION;

typedef struct _EPROCESS_FLAGS2 {
    unsigned int JobNotReallyActive           : 1;
    unsigned int AccountingFolded             : 1;
    unsigned int NewProcessReported           : 1;
    unsigned int ExitProcessReported          : 1;
    unsigned int ReportCommitChanges          : 1;
    unsigned int LastReportMemory             : 1;
    unsigned int ForceWakeCharge              : 1;
    unsigned int CrossSessionCreate           : 1;
    unsigned int NeedsHandleRundown           : 1;
    unsigned int RefTraceEnabled              : 1;
    unsigned int DisableDynamicCode           : 1;
    unsigned int EmptyJobEvaluated            : 1;
    unsigned int DefaultPagePriority          : 3;
    unsigned int PrimaryTokenFrozen           : 1;
    unsigned int ProcessVerifierTarget        : 1;
    unsigned int StackRandomizationDisabled   : 1;
    unsigned int AffinityPermanent            : 1;
    unsigned int AffinityUpdateEnable         : 1;
    unsigned int PropagateNode                : 1;
    unsigned int ExplicitAffinity             : 1;
    unsigned int ProcessExecutionState        : 2;
    unsigned int DisallowStrippedImages       : 1;
    unsigned int HighEntropyASLREnabled       : 1;
    unsigned int ExtensionPointDisable        : 1;
    unsigned int ForceRelocateImages          : 1;
    unsigned int ProcessStateChangeRequest    : 2;
    unsigned int ProcessStateChangeInProgress : 1;
    unsigned int DisallowWin32kSystemCalls    : 1;
} EPROCESS_FLAGS2, *PEPROCESS_FLAGS2;

typedef struct _MITIGATION_FLAGS {
    unsigned int ControlFlowGuardEnabled                  : 1;
    unsigned int ControlFlowGuardExportSuppressionEnabled : 1;
    unsigned int ControlFlowGuardStrict                   : 1;
    unsigned int DisallowStrippedImages                   : 1;
    unsigned int ForceRelocateImages                      : 1;
    unsigned int HighEntropyASLREnabled                   : 1;
    unsigned int StackRandomizationDisabled               : 1;
    unsigned int ExtensionPointDisable                    : 1;
    unsigned int DisableDynamicCode                       : 1;
    unsigned int DisableDynamicCodeAllowOptOut            : 1;
    unsigned int DisableDynamicCodeAllowRemoteDowngrade   : 1;
    unsigned int AuditDisableDynamicCode                  : 1;
    unsigned int DisallowWin32kSystemCalls                : 1;
    unsigned int AuditDisallowWin32kSystemCalls           : 1;
    unsigned int EnableFilteredWin32kAPIs                 : 1;
    unsigned int AuditFilteredWin32kAPIs                  : 1;
    unsigned int DisableNonSystemFonts                    : 1;
    unsigned int AuditNonSystemFontLoading                : 1;
    unsigned int PreferSystem32Images                     : 1;
    unsigned int ProhibitRemoteImageMap                   : 1;
    unsigned int AuditProhibitRemoteImageMap              : 1;
    unsigned int ProhibitLowILImageMap                    : 1;
    unsigned int AuditProhibitLowILImageMap               : 1;
    unsigned int SignatureMitigationOptIn                 : 1;
    unsigned int AuditBlockNonMicrosoftBinaries           : 1;
    unsigned int AuditBlockNonMicrosoftBinariesAllowStore : 1;
    unsigned int LoaderIntegrityContinuityEnabled         : 1;
    unsigned int AuditLoaderIntegrityContinuity           : 1;
    unsigned int EnableModuleTamperingProtection          : 1;
    unsigned int EnableModuleTamperingProtectionNoInherit : 1;
    unsigned int RestrictIndirectBranchPrediction;
    unsigned int IsolateSecurityDomain;
} MITIGATION_FLAGS, *PMITIGATION_FLAGS;

typedef union _EXHANDLE {
    struct {
        int TagBits : 2;
        int Index   : 30;
    } u;
    void     *GenericHandleOverlay;
    ULONG_PTR Value;
} EXHANDLE, *PEXHANDLE;

#pragma warning(disable : 4201)
typedef struct _HANDLE_TABLE_ENTRY // Size=16
{
    union {
        ULONG_PTR                        VolatileLowValue; // Size=8 Offset=0
        ULONG_PTR                        LowValue;         // Size=8 Offset=0
        struct _HANDLE_TABLE_ENTRY_INFO *InfoTable;        // Size=8 Offset=0
        struct {
            ULONG_PTR Unlocked          : 1;  // Size=8 Offset=0 BitOffset=0 BitCount=1
            ULONG_PTR RefCnt            : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
            ULONG_PTR Attributes        : 3;  // Size=8 Offset=0 BitOffset=17 BitCount=3
            ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
        };
    };
    union {
        ULONG_PTR                   HighValue;           // Size=8 Offset=8
        struct _HANDLE_TABLE_ENTRY *NextFreeHandleEntry; // Size=8 Offset=8
        union _EXHANDLE             LeafHandleValue;     // Size=8 Offset=8
        struct {
            ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
            ULONG NoRightsUpgrade   : 1;  // Size=4 Offset=8 BitOffset=25 BitCount=1
            ULONG Spare             : 6;  // Size=4 Offset=8 BitOffset=26 BitCount=6
        };
    };
    ULONG TypeInfo; // Size=4 Offset=12
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
#pragma warning(default : 4201)

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE {
    PULONG_PTR ServiceTableBase;
    PULONG     ServiceCounterTableBase;
    ULONG_PTR  NumberOfServices;
    PUCHAR     ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section; // Not filled in
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG                          NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY {
    ULONG     Attribute; // PROC_THREAD_ATTRIBUTE_XXX
    SIZE_T    Size;
    ULONG_PTR Value;
    ULONG     Unknown;
} NT_PROC_THREAD_ATTRIBUTE_ENTRY, *NT_PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST {
    ULONG                          Length;
    NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, *PNT_PROC_THREAD_ATTRIBUTE_LIST;


NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewAccessProtection, PULONG OldAccessProtection);
NTSTATUS NTAPI ZwLockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG LockOption);
NTSTATUS NTAPI ZwUnlockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG LockOption);