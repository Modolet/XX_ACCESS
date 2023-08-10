#include "hook.h"
#include "MinHook.h"
#include "cepluginsdk.h"

#include "DriverControl.h"

extern ExportedFunctions Exported;
bool                     hookStatus = true;
#define HANDLE_SIGNATURE      (1 << 31 | 1 << 29)
#define IsValidHandle(handle) (((SIZE_T)handle & HANDLE_SIGNATURE) && ((SIZE_T)handle % 4 == 0))
#define EncodeHandle(id)      (HANDLE)((SIZE_T)id | HANDLE_SIGNATURE)
#define DecodeHandle(handle)  (HANDLE)((SIZE_T)handle & ~HANDLE_SIGNATURE)

bool hook(const wchar_t *dllName, const char *name, PVOID *orgFunc, PVOID newFunc) {
    if (MH_CreateHookApi(dllName, name, newFunc, orgFunc) != MH_OK) {
        MessageBoxA(NULL, name, "HOOK ß∞‹",0);
        hookStatus = false;
        return false;
    }
    return true;
}

NTSTATUS(NTAPI *NtOpenProcess)
(PHANDLE processHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID clientId);
NTSTATUS NTAPI NtOpenProcessHook(PHANDLE processHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes,
                                 PCLIENT_ID clientId) {
    if (clientId->UniqueProcess == (HANDLE)(SIZE_T)GetCurrentProcessId()) {
        return NtOpenProcess(processHandle, desiredAccess, objectAttributes, clientId);
    }
    return DriverControl::Instance().IONtOpenProcess(processHandle, desiredAccess, objectAttributes, clientId);
}

NTSTATUS(NTAPI *NtSuspendProcess)(HANDLE processHandle);
NTSTATUS NTAPI NtSuspendProcessHook(HANDLE processHandle) {
    if (!IsValidHandle(processHandle)) {
        return NtSuspendProcess(processHandle);
    }
    return DriverControl::Instance().IONtSuspendProcess(processHandle);
}

NTSTATUS(NTAPI *NtResumeProcess)(HANDLE processHandle);
NTSTATUS NTAPI NtResumeProcessHook(HANDLE processHandle) {
    if (!IsValidHandle(processHandle)) {
        return NtResumeProcess(processHandle);
    }
    return DriverControl::Instance().IONtResumeProcess(processHandle);
}

NTSTATUS(NTAPI *NtQuerySystemInformationEx)
(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID inputBuffer, ULONG inputBufferLength, PVOID systemInformation,
 ULONG systemInformationLength, PULONG returnLength);
NTSTATUS NTAPI NtQuerySystemInformationExHook(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID inputBuffer,
                                              ULONG inputBufferLength, PVOID systemInformation, ULONG systemInformationLength,
                                              PULONG returnLength) {
    switch (systemInformationClass) {
    case SystemSupportedProcessArchitectures:
        if (inputBuffer && inputBufferLength >= sizeof(HANDLE) && IsValidHandle(*(PHANDLE)inputBuffer)) {
            return DriverControl::Instance().IONtQuerySystemInformationEx(
                systemInformationClass, inputBuffer, inputBufferLength, systemInformation, systemInformationLength, returnLength);
        }
        break;
    }
    return NtQuerySystemInformationEx(systemInformationClass, inputBuffer, inputBufferLength, systemInformation,
                                      systemInformationLength, returnLength);
}

NTSTATUS(NTAPI *NtQueryInformationProcess)
(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID processInformation, ULONG processInformationLength,
 PULONG returnLength);
NTSTATUS NTAPI NtQueryInformationProcessHook(HANDLE processHandle, PROCESSINFOCLASS processInformationClass,
                                             PVOID processInformation, ULONG processInformationLength, PULONG returnLength) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtQueryInformationProcess(processHandle, processInformationClass, processInformation, processInformationLength,
                                         returnLength);
    }
    return DriverControl::Instance().IONtQueryInformationProcess(processHandle, processInformationClass, processInformation,
                                                                 processInformationLength, returnLength);
}

NTSTATUS(NTAPI *NtSetInformationProcess)
(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID processInformation, ULONG processInformationLength);
NTSTATUS NTAPI NtSetInformationProcessHook(HANDLE processHandle, PROCESSINFOCLASS processInformationClass,
                                           PVOID processInformation, ULONG processInformationLength) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtSetInformationProcess(processHandle, processInformationClass, processInformation, processInformationLength);
    }
    return DriverControl::Instance().IONtSetInformationProcess(processHandle, processInformationClass, processInformation,
                                                               processInformationLength);
}

NTSTATUS(NTAPI *NtFlushInstructionCache)(HANDLE processHandle, PVOID baseAddress, ULONG numberOfBytesToFlush);
NTSTATUS NTAPI NtFlushInstructionCacheHook(HANDLE processHandle, PVOID baseAddress, ULONG numberOfBytesToFlush) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtFlushInstructionCache(processHandle, baseAddress, numberOfBytesToFlush);
    }
    return DriverControl::Instance().IONtFlushInstructionCache(processHandle, baseAddress, numberOfBytesToFlush);
}

NTSTATUS(NTAPI *NtClose)(HANDLE handle);
NTSTATUS NTAPI NtCloseHook(HANDLE handle) {
    if (!IsValidHandle(handle)) {
        return NtClose(handle);
    }
    return ERROR_SUCCESS;
}

/*** Memory ***/
NTSTATUS(NTAPI *NtAllocateVirtualMemory)
(HANDLE processHandle, PVOID baseAddress, SIZE_T zeroBits, PSIZE_T regionSize, ULONG allocationType, ULONG protect);
NTSTATUS NTAPI NtAllocateVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, SIZE_T zeroBits, PSIZE_T regionSize,
                                           ULONG allocationType, ULONG protect) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtAllocateVirtualMemory(processHandle, baseAddress, zeroBits, regionSize, allocationType, protect);
    }
    return DriverControl::Instance().IONtAllocateVirtualMemory(processHandle, baseAddress, zeroBits, regionSize, allocationType,
                                                               protect);
}

NTSTATUS(NTAPI *NtFlushVirtualMemory)(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, PIO_STATUS_BLOCK ioStatus);
NTSTATUS NTAPI NtFlushVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, PIO_STATUS_BLOCK ioStatus) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtFlushVirtualMemory(processHandle, baseAddress, regionSize, ioStatus);
    }
    return DriverControl::Instance().IONtFlushVirtualMemory(processHandle, baseAddress, regionSize, ioStatus);
}

NTSTATUS(NTAPI *NtFreeVirtualMemory)(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG freeType);
NTSTATUS NTAPI NtFreeVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG freeType) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtFreeVirtualMemory(processHandle, baseAddress, regionSize, freeType);
    }
    return DriverControl::Instance().IONtFreeVirtualMemory(processHandle, baseAddress, regionSize, freeType);
}

NTSTATUS(NTAPI *NtLockVirtualMemory)(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption);
NTSTATUS NTAPI NtLockVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtLockVirtualMemory(processHandle, baseAddress, regionSize, lockOption);
    }
    return DriverControl::Instance().IONtLockVirtualMemory(processHandle, baseAddress, regionSize, lockOption);
}

NTSTATUS(NTAPI *NtUnlockVirtualMemory)(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption);
NTSTATUS NTAPI NtUnlockVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtUnlockVirtualMemory(processHandle, baseAddress, regionSize, lockOption);
    }
    return DriverControl::Instance().IONtUnlockVirtualMemory(processHandle, baseAddress, regionSize, lockOption);
}

NTSTATUS(NTAPI *NtProtectVirtualMemory)
(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG newAccessProtection, PULONG oldAccessProtection);
NTSTATUS NTAPI NtProtectVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG newAccessProtection,
                                          PULONG oldAccessProtection) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtProtectVirtualMemory(processHandle, baseAddress, regionSize, newAccessProtection, oldAccessProtection);
    }
    return DriverControl::Instance().IONtProtectVirtualMemory(processHandle, baseAddress, regionSize, newAccessProtection,
                                                              oldAccessProtection);
}

NTSTATUS(NTAPI *NtReadVirtualMemory)
(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToRead, PSIZE_T numberOfBytesRead);
NTSTATUS NTAPI NtReadVirtualMemoryHook(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToRead,
                                       PSIZE_T numberOfBytesRead) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtReadVirtualMemory(processHandle, baseAddress, buffer, numberOfBytesToRead, numberOfBytesRead);
    }
    return DriverControl::Instance().IONtReadVirtualMemory(processHandle, baseAddress, buffer, numberOfBytesToRead,
                                                           numberOfBytesRead);
}

NTSTATUS(NTAPI *NtWriteVirtualMemory)
(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToWrite, PSIZE_T numberOfBytesWritten);
NTSTATUS NTAPI NtWriteVirtualMemoryHook(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToWrite,
                                        PSIZE_T numberOfBytesWritten) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtWriteVirtualMemory(processHandle, baseAddress, buffer, numberOfBytesToWrite, numberOfBytesWritten);
    }
    return DriverControl::Instance().IONtWriteVirtualMemory(processHandle, baseAddress, buffer, numberOfBytesToWrite,
                                                            numberOfBytesWritten);
}

NTSTATUS(NTAPI *NtQueryVirtualMemory)
(HANDLE processHandle, PVOID baseAddress, MEMORY_INFORMATION_CLASS memoryInformationClass, PVOID memoryInformation,
 SIZE_T memoryInformationLength, PSIZE_T returnLength);
NTSTATUS NTAPI NtQueryVirtualMemoryHook(HANDLE processHandle, PVOID baseAddress, MEMORY_INFORMATION_CLASS memoryInformationClass,
                                        PVOID memoryInformation, SIZE_T memoryInformationLength, PSIZE_T returnLength) {
    if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
        return NtQueryVirtualMemory(processHandle, baseAddress, memoryInformationClass, memoryInformation,
                                    memoryInformationLength, returnLength);
    }
    return DriverControl::Instance().IONtQueryVirtualMemory(processHandle, baseAddress, memoryInformationClass, memoryInformation,
                                                            memoryInformationLength, returnLength);
}

/*** Thread ***/
NTSTATUS(NTAPI *NtOpenThread)
(PHANDLE threadHandle, ACCESS_MASK accessMask, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID clientId);
NTSTATUS NTAPI NtOpenThreadHook(PHANDLE threadHandle, ACCESS_MASK accessMask, POBJECT_ATTRIBUTES objectAttributes,
                                PCLIENT_ID clientId) {
    if (clientId->UniqueProcess == GetCurrentProcess() || clientId->UniqueThread == (HANDLE)(SIZE_T)GetCurrentThreadId()) {
        return NtOpenThread(threadHandle, accessMask, objectAttributes, clientId);
    }
    return DriverControl::Instance().IONtOpenThread(threadHandle, accessMask, objectAttributes, clientId);
}

NTSTATUS(NTAPI *NtCreateThreadEx)
(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress,
 PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
NTSTATUS NtCreateThreadExHook(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes,
                               IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags,
                               IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve,
                               OUT PVOID lpBytesBuffer) {
    if (!IsValidHandle(ProcessHandle)) {
        return NtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags,
                                StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
    }
    return DriverControl::Instance().IoNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress,
                                                        lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve,
                                                        lpBytesBuffer);
}

NTSTATUS(NTAPI *NtQueryInformationThread)
(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength,
 PULONG returnLength);
NTSTATUS NTAPI NtQueryInformationThreadHook(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation,
                                            ULONG threadInformationLength, PULONG returnLength) {
    if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
        return NtQueryInformationThread(threadHandle, threadInformationClass, threadInformation, threadInformationLength,
                                        returnLength);
    }
    return DriverControl::Instance().IONtQueryInformationThread(threadHandle, threadInformationClass, threadInformation,
                                                                threadInformationLength, returnLength);
}

NTSTATUS(NTAPI *NtSetInformationThread)
(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);
NTSTATUS NTAPI NtSetInformationThreadHook(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation,
                                          ULONG threadInformationLength) {
    if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
        return NtSetInformationThread(threadHandle, threadInformationClass, threadInformation, threadInformationLength);
    }
    return DriverControl::Instance().IONtSetInformationThread(threadHandle, threadInformationClass, threadInformation,
                                                              threadInformationLength);
}

NTSTATUS(NTAPI *NtGetContextThread)(HANDLE threadHandle, PCONTEXT context);
NTSTATUS NTAPI NtGetContextThreadHook(HANDLE threadHandle, PCONTEXT context) {
    if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
        return NtGetContextThread(threadHandle, context);
    }
    return DriverControl::Instance().IONtGetContextThread(threadHandle, context);
}

NTSTATUS(NTAPI *NtSetContextThread)(HANDLE threadHandle, PCONTEXT context);
NTSTATUS NTAPI NtSetContextThreadHook(HANDLE threadHandle, PCONTEXT context) {
    if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
        return NtSetContextThread(threadHandle, context);
    }
    return DriverControl::Instance().IONtSetContextThread(threadHandle, context);
}

NTSTATUS(NTAPI *NtResumeThread)(HANDLE threadHandle, PULONG suspendCount);
NTSTATUS NTAPI NtResumeThreadHook(HANDLE threadHandle, PULONG suspendCount) {
    if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
        return NtResumeThread(threadHandle, suspendCount);
    }
    return DriverControl::Instance().IONtResumeThread(threadHandle, suspendCount);
}

NTSTATUS(NTAPI *NtSuspendThread)(HANDLE threadHandle, PULONG previousSuspendCount);
NTSTATUS NTAPI NtSuspendThreadHook(HANDLE threadHandle, PULONG previousSuspendCount) {
    if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
        return NtSuspendThread(threadHandle, previousSuspendCount);
    }
    return DriverControl::Instance().IONtSuspendThread(threadHandle, previousSuspendCount);
}

/*** Sync ***/
NTSTATUS(NTAPI *NtWaitForSingleObject)(HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout);
NTSTATUS NTAPI NtWaitForSingleObjectHook(HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout) {
    if (!IsValidHandle(handle)) {
        return NtWaitForSingleObject(handle, alertable, timeout);
    }
    return DriverControl::Instance().IONtWaitForSingleObject(handle, alertable, timeout);
}

/*** Handle ***/
NTSTATUS(NTAPI *NtDuplicateObject)
(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
 ULONG HandleAttributes, ULONG Options);
NTSTATUS NtDuplicateObjectHook(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle,
                               ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) {
    if (!IsValidHandle(TargetProcessHandle)) {
        return NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess,
                                 HandleAttributes, Options);
    }
    auto status = DriverControl::Instance().IONtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle,
                                                                TargetHandle, DesiredAccess, HandleAttributes, Options);
    // char out[1024];
    // sprintf(out, "status:%x", status);
    // MessageBoxA(0, out, out, 0);
    return status;
}

BOOL IsWow64ProcessHook(HANDLE hProcess, PBOOL Wow64Process);
HANDLE(*CreateRemoteThreadOrg)
(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
 LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE CreateRemoteThreadHook(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                              LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
                              LPDWORD lpThreadId) {
    if (!IsValidHandle(hProcess)) {
        return CreateRemoteThreadOrg(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags,
                                     lpThreadId);
    }
    auto    pid = DecodeHandle(hProcess);
    ULONG64 ret;
    HMODULE module = (HMODULE)LoadLibraryA("Kernel32.dll");
    if (module == INVALID_HANDLE_VALUE || module == NULL) {
        return NULL;
    }
    auto addr = GetProcAddress(module, "CreateThread");
    if (addr == 0) {
        return NULL;
    }
    auto mem = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem == 0) {
        return NULL;
    }
    BYTE pBuffer[] = {0x48, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00, 0x48, 0x31, 0xC0, 0x48, 0x89, 0x44, 0x24, 0x28,
                      0x48, 0x89, 0x44, 0x24, 0x20, 0x4D, 0x31, 0xC9, 0x49, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x00,
                      0x00, 0x00, 0x00, 0x48, 0x31, 0xD2, 0x48, 0x31, 0xC9, 0x48, 0xB8, 0x11, 0x11, 0x11, 0x11,
                      0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x81, 0xC4, 0x00, 0x02, 0x00, 0x00, 0xC3};
    *(ULONGLONG *)((PUCHAR)pBuffer + 25)   = (ULONGLONG)lpStartAddress;
    *(ULONGLONG *)((PUCHAR)pBuffer + 0x29) = (ULONGLONG)addr;

    BYTE pBUffer32[] = { 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x68, 0x44, 0x33, 0x22, 0x11, 0x6a, 0x00, 0x6a, 0x00,0xb8,0x00,0x00,0x00,0x00, 0xFF,0xD0, 0xc3 };

    *(ULONG*)((PUCHAR)pBUffer32 + 7) = (ULONG)lpStartAddress;
    *(ULONG*)((PUCHAR)pBUffer32 + 16) = (ULONG)addr;
    BOOL wow64 = FALSE;
    IsWow64ProcessHook(hProcess, &wow64);
    if (wow64) {
        WriteProcessMemory(hProcess, mem, pBUffer32, sizeof(pBUffer32), (SIZE_T*)&ret);
    }
    else {
        WriteProcessMemory(hProcess, mem, pBuffer, sizeof(pBuffer), (SIZE_T*)&ret);
    }
    DriverControl::Instance().IORemoteCall(pid, (ULONG64)mem, &ret);
    return (HANDLE)99999;
    
}

BOOL (*IsWow64ProcessOrg)( HANDLE hProcess,  PBOOL Wow64Process);
BOOL IsWow64ProcessHook(HANDLE hProcess, PBOOL Wow64Process) {
    if (!IsValidHandle(hProcess)) {
        return IsWow64ProcessOrg(hProcess, Wow64Process);
    }
    return DriverControl::Instance().IOIsWow64Process(hProcess, Wow64Process);
}

static bool hookInit = false;

bool Attach() {
    static auto init = MH_Initialize();
    if (init != MH_OK) {
        MessageBoxW(NULL, L"≥ı ºªØHOOK ß∞‹", 0, 0);
    }
    if (hookInit) {
        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
            MessageBoxW(NULL, L"º§ªÓHOOK ß∞‹", 0, 0);
            return false;
        }
        return true;
    }
    hook(L"Kernel32.dll", "CreateRemoteThread", (PVOID *)&CreateRemoteThreadOrg, CreateRemoteThreadHook);
    hook(L"Kernel32.dll", "IsWow64Process", (PVOID *)&IsWow64ProcessOrg, IsWow64ProcessHook);
    hook(L"ntdll.dll", "NtOpenProcess", (PVOID *)&NtOpenProcess, NtOpenProcessHook);
    hook(L"ntdll.dll", "NtSuspendProcess", (PVOID *)&NtSuspendProcess, NtSuspendProcessHook);
    hook(L"ntdll.dll", "NtResumeProcess", (PVOID *)&NtResumeProcess, NtResumeProcessHook);
    hook(L"ntdll.dll", "NtQuerySystemInformationEx", (PVOID *)&NtQuerySystemInformationEx, NtQuerySystemInformationExHook);
    hook(L"ntdll.dll", "NtQueryInformationProcess", (PVOID *)&NtQueryInformationProcess, NtQueryInformationProcessHook);
    hook(L"ntdll.dll", "NtSetInformationProcess", (PVOID *)&NtSetInformationProcess, NtSetInformationProcessHook);
    hook(L"ntdll.dll", "NtFlushInstructionCache", (PVOID *)&NtFlushInstructionCache, NtFlushInstructionCacheHook);
    hook(L"ntdll.dll", "NtClose", (PVOID *)&NtClose, NtCloseHook);
    /*** Memory ***/
    hook(L"ntdll.dll", "NtAllocateVirtualMemory", (PVOID *)&NtAllocateVirtualMemory, NtAllocateVirtualMemoryHook);
    hook(L"ntdll.dll", "NtFlushVirtualMemory", (PVOID *)&NtFlushVirtualMemory, NtFlushVirtualMemoryHook);
    hook(L"ntdll.dll", "NtFreeVirtualMemory", (PVOID *)&NtFreeVirtualMemory, NtFreeVirtualMemoryHook);
    hook(L"ntdll.dll", "NtLockVirtualMemory", (PVOID *)&NtLockVirtualMemory, NtLockVirtualMemoryHook);
    hook(L"ntdll.dll", "NtUnlockVirtualMemory", (PVOID *)&NtUnlockVirtualMemory, NtUnlockVirtualMemoryHook);
    hook(L"ntdll.dll", "NtProtectVirtualMemory", (PVOID *)&NtProtectVirtualMemory, NtProtectVirtualMemoryHook);
    hook(L"ntdll.dll", "NtReadVirtualMemory", (PVOID *)&NtReadVirtualMemory, NtReadVirtualMemoryHook);
    hook(L"ntdll.dll", "NtWriteVirtualMemory", (PVOID *)&NtWriteVirtualMemory, NtWriteVirtualMemoryHook);
    hook(L"ntdll.dll", "NtQueryVirtualMemory", (PVOID *)&NtQueryVirtualMemory, NtQueryVirtualMemoryHook);

    /*** Thread ***/
    hook(L"ntdll.dll", "NtOpenThread", (PVOID *)&NtOpenThread, NtOpenThreadHook);
    hook(L"ntdll.dll", "NtCreateThreadEx", (PVOID *)&NtCreateThreadEx, NtCreateThreadExHook);
    hook(L"ntdll.dll", "NtQueryInformationThread", (PVOID *)&NtQueryInformationThread, NtQueryInformationThreadHook);
    hook(L"ntdll.dll", "NtSetInformationThread", (PVOID *)&NtSetInformationThread, NtSetInformationThreadHook);
    hook(L"ntdll.dll", "NtGetContextThread", (PVOID *)&NtGetContextThread, NtGetContextThreadHook);
    hook(L"ntdll.dll", "NtSetContextThread", (PVOID *)&NtSetContextThread, NtSetContextThreadHook);
    hook(L"ntdll.dll", "NtSuspendThread", (PVOID *)&NtSuspendThread, NtSuspendThreadHook);
    hook(L"ntdll.dll", "NtResumeThread", (PVOID *)&NtResumeThread, NtResumeThreadHook);

    /*** Sync ***/
    hook(L"ntdll.dll", "NtWaitForSingleObject", (PVOID *)&NtWaitForSingleObject, NtWaitForSingleObjectHook);

    /*** Handle ***/
    hook(L"ntdll.dll", "NtDuplicateObject", (PVOID *)&NtDuplicateObject, NtDuplicateObjectHook);




    if (!hookStatus || MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        MessageBoxW(NULL, L"º§ªÓHOOK ß∞‹", 0, 0);
        return false;
    }
    hookInit = true;
    return true;
}

bool Detach() {
    return MH_DisableHook(MH_ALL_HOOKS) == MH_OK;
}