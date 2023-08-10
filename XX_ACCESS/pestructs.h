#pragma once
typedef struct tagACTCTXW {
    ULONG  cbSize;
    ULONG  dwFlags;
    PWCH   lpSource;
    USHORT wProcessorArchitecture;
    USHORT wLangId;
    PWCH   lpAssemblyDirectory;
    PWCH   lpResourceName;
    PWCH   lpApplicationName;
    PVOID  hModule;
} ACTCTXW, *PACTCTXW;

typedef struct tagACTCTXW32 {
    ULONG  cbSize;
    ULONG  dwFlags;
    ULONG  lpSource;
    USHORT wProcessorArchitecture;
    USHORT wLangId;
    ULONG  lpAssemblyDirectory;
    ULONG  lpResourceName;
    ULONG  lpApplicationName;
    ULONG  hModule;
} ACTCTXW32, *PACTCTXW32;