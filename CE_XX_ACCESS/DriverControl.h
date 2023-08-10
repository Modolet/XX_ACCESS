#pragma once


#include "HandleGuard.h"

#include <map>
#include <shlwapi.h>
#include <string>
#include <vector>

class DriverControl {
public:
    DriverControl();
    ~DriverControl();

    static DriverControl &Instance();
    NTSTATUS              EnsureLoaded(const std::wstring &path);
    NTSTATUS              LoadDriver(const std::wstring &svcName, const std::wstring &path);
    NTSTATUS              Reload(std::wstring path);
    NTSTATUS              Unload();
    inline bool           loaded() const {
        return _hDriver.valid();
    }
    inline NTSTATUS status() const {
        return _loadStatus;
    }

    /*** Extern ***/
    NTSTATUS IORemoteCall(HANDLE pid, ULONG64 address, ULONG64 *pRetVal);
    NTSTATUS IOProtectProcess(ULONG pid);
    NTSTATUS IOUnProtectProcess(ULONG pid);
    /*** Process ***/
    NTSTATUS IONtOpenProcess(PHANDLE processHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes,
                             PCLIENT_ID clientId);
    NTSTATUS IONtSuspendProcess(HANDLE processHandle);
    NTSTATUS IONtResumeProcess(HANDLE processHandle);
    NTSTATUS IONtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID inputBuffer,
                                          ULONG inputBufferLength, PVOID systemInformation, ULONG systemInformationLength,
                                          PULONG returnLength);
    NTSTATUS IONtQueryInformationProcess(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID processInformation,
                                         ULONG processInformationLength, PULONG returnLength);
    NTSTATUS IONtSetInformationProcess(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID processInformation,
                                       ULONG processInformationLength);
    NTSTATUS IONtFlushInstructionCache(HANDLE processHandle, PVOID baseAddress, ULONG numberOfBytesToFlush);

    /*** Memory ***/
    NTSTATUS IONtAllocateVirtualMemory(HANDLE processHandle, PVOID *baseAddress, SIZE_T zeroBits, PSIZE_T regionSize,
                                       ULONG allocationType, ULONG protect);
    NTSTATUS IONtFlushVirtualMemory(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, PIO_STATUS_BLOCK ioStatus);
    NTSTATUS IONtFreeVirtualMemory(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG freeType);
    NTSTATUS IONtLockVirtualMemory(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption);
    NTSTATUS IONtUnlockVirtualMemory(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption);
    NTSTATUS IONtProtectVirtualMemory(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG newAccessProtection,
                                      PULONG oldAccessProtection);
    NTSTATUS IONtReadVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToRead,
                                   PSIZE_T numberOfBytesRead);
    NTSTATUS IONtWriteVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToWrite,
                                    PSIZE_T numberOfBytesWritten);
    NTSTATUS IONtQueryVirtualMemory(HANDLE processHandle, PVOID baseAddress, MEMORY_INFORMATION_CLASS memoryInformationClass,
                                    PVOID memoryInformation, SIZE_T memoryInformationLength, PSIZE_T returnLength);

    /*** Thread ***/
    NTSTATUS IONtOpenThread(PHANDLE threadHandle, ACCESS_MASK accessMask, POBJECT_ATTRIBUTES objectAttributes,
                            PCLIENT_ID clientId);
    NTSTATUS IoNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle,
                                PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits,
                                SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
    NTSTATUS IONtQueryInformationThread(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation,
                                        ULONG threadInformationLength, PULONG returnLength);
    NTSTATUS IONtSetInformationThread(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation,
                                      ULONG threadInformationLength);
    NTSTATUS IONtGetContextThread(HANDLE threadHandle, PCONTEXT context);
    NTSTATUS IONtSetContextThread(HANDLE threadHandle, PCONTEXT context);
    NTSTATUS IONtResumeThread(HANDLE threadHandle, PULONG suspendCount);
    NTSTATUS IONtSuspendThread(HANDLE threadHandle, PULONG previousSuspendCount);

    /*** Sync ***/
    NTSTATUS IONtWaitForSingleObject(HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout);
    /*** Handle ***/
    NTSTATUS IONtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
                                 PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
    BOOL IOIsWow64Process(HANDLE hProcess, PBOOL Wow64Process);


private:
    DriverControl(const DriverControl &)            = delete;
    DriverControl &operator=(const DriverControl &) = delete;
    NTSTATUS       UnloadDriver(const std::wstring &svcName);

private:
    Handle   _hDriver;
    NTSTATUS _loadStatus = STATUS_NOT_FOUND;
};
