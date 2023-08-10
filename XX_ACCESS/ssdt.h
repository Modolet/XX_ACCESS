#pragma once
#include <ntifs.h>
#include <windef.h>

namespace SSDT {
ULONG GetSSDTFunctionIndexAndAdd(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName);
PVOID     GetSSDTEntry(IN ULONG index);
}; // namespace SSDT
