

#include "DriverControl.h"
#include "../XX_ACCESS/def.h"
#include "trace.hpp"

#define DRIVER_SVC_NAME L"XX_ACCESS"

#define LAST_STATUS_OFS (0x598 + 0x197 * sizeof(void *))
inline NTSTATUS LastNtStatus() {
    return *(NTSTATUS *)((unsigned char *)NtCurrentTeb() + LAST_STATUS_OFS);
}

DriverControl::DriverControl() {
    _hDriver.reset();
}

DriverControl::~DriverControl() {
}

DriverControl &DriverControl::Instance() {
    static DriverControl instance;
    return instance;
}

NTSTATUS
DriverControl::EnsureLoaded(const std::wstring &path) {
    // Already open
    if (_hDriver) {
        return STATUS_SUCCESS;
    }

    // Try to open handle to existing driver
    _hDriver = CreateFileW(XX_DEVICE_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           0, NULL);

    if (_hDriver) {
        return _loadStatus = STATUS_SUCCESS;
    }

    // Start new instance
    return Reload(path);
}

NTSTATUS
DriverControl::LoadDriver(const std::wstring &svcName, const std::wstring &path) {
    const wchar_t *lpszDriverName = svcName.c_str();
    const wchar_t *lpszDriverPath = path.c_str();
    wchar_t        szDriverImagePath[256];
    // �õ�����������·��
    GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);
    NTSTATUS status = STATUS_SUCCESS;

    SC_HANDLE hServiceMgr = NULL; // SCM�������ľ��
    SC_HANDLE hServiceDDK = NULL; // NT��������ķ�����

    // �򿪷�����ƹ�����
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (hServiceMgr == NULL) {
        status = GetLastError();
        goto BeforeLeave;
    }
    // ������������Ӧ�ķ���
    hServiceDDK = CreateService(hServiceMgr,
                                lpszDriverName,        // �����������ע����е�����
                                lpszDriverName,        // ע������������ DisplayName ֵ
                                SERVICE_ALL_ACCESS,    // ������������ķ���Ȩ��
                                SERVICE_KERNEL_DRIVER, // ��ʾ���صķ�������������
                                SERVICE_DEMAND_START,  // ע������������ Start ֵ
                                SERVICE_ERROR_IGNORE,  // ע������������ ErrorControl ֵ
                                szDriverImagePath,     // ע������������ ImagePath ֵ
                                NULL, NULL, NULL, NULL, NULL);

    DWORD dwRtn;
    // �жϷ����Ƿ�ʧ��
    if (hServiceDDK == NULL) {
        dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS) {
            // ��������ԭ�򴴽�����ʧ��
            status = dwRtn;
            goto BeforeLeave;
        } else {
            // ���񴴽�ʧ�ܣ������ڷ����Ѿ�������
        }
        // ���������Ѿ����أ�ֻ��Ҫ��
        hServiceDDK = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
        if (hServiceDDK == NULL) {
            // ����򿪷���Ҳʧ�ܣ�����ζ����
            dwRtn  = GetLastError();
            status = dwRtn;
            goto BeforeLeave;
        } else {
        }
    } else {
    }
    // �����������
    if (!StartService(hServiceDDK, NULL, NULL)) {
        DWORD dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING) {
            status = 1;
            goto BeforeLeave;
        } else {
            if (dwRtn == ERROR_IO_PENDING) {
                // �豸����ס
                status = dwRtn;
                goto BeforeLeave;
            } else {
                // �����Ѿ�����
                status = STATUS_SUCCESS;
                goto BeforeLeave;
            }
        }
    }
    status = STATUS_SUCCESS;
    // �뿪ǰ�رվ��
BeforeLeave:
    if (hServiceDDK) {
        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr) {
        CloseServiceHandle(hServiceMgr);
    }
    return status;
}

NTSTATUS
DriverControl::Reload(std::wstring path) {
    Unload();
    _loadStatus = LoadDriver(DRIVER_SVC_NAME, path);
    if (_loadStatus) {
        TRACE(L"Failed to load driver %ls. Status 0x%X", path.c_str(), _loadStatus);
        return _loadStatus;
    }

    _hDriver = CreateFileW(XX_DEVICE_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           0, NULL);
    if (!_hDriver) {
        _loadStatus = LastNtStatus();
        TRACE(L"Failed to open driver handle. Status 0x%X", _loadStatus);
        return _loadStatus;
    }

    return _loadStatus;
}

NTSTATUS
DriverControl::Unload() {
    _hDriver.reset();
    return UnloadDriver(DRIVER_SVC_NAME);
}

NTSTATUS DriverControl::IORemoteCall(HANDLE pid, ULONG64 address,ULONG64* pRetVal) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD          bytes = 0;
    _I_INJECT_CODE args;
    _O_INJECT_CODE ret;
    args.pid  = (ULONG)pid;
    args.addr = address;
    if (!DeviceIoControl(_hDriver, IOCTL_INJECTCODE, &args, sizeof(args), &ret, sizeof(ret), &bytes, NULL)) {
        return LastNtStatus();
    }
    *pRetVal = ret.returnVal;
    return STATUS_SUCCESS;
}

NTSTATUS DriverControl::IOProtectProcess(ULONG pid) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                bytes = 0;
    IO_PROTECT_PROC args;
    args.pid = pid;
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    if (!DeviceIoControl(_hDriver, IOCTL_PROTECTPROC, &args, sizeof(args), NULL, 0, &bytes, NULL)) {
        return LastNtStatus();
    }
    return STATUS_SUCCESS;
}

NTSTATUS DriverControl::IOUnProtectProcess(ULONG pid) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD           bytes = 0;
    IO_PROTECT_PROC args;
    args.pid = pid;
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    if (!DeviceIoControl(_hDriver, IOCTL_UNPROTECTPROC, &args, sizeof(args), NULL, 0, &bytes, NULL)) {
        return LastNtStatus();
    }
    return STATUS_SUCCESS;
}

NTSTATUS DriverControl::IONtOpenProcess(PHANDLE processHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes,
                                        PCLIENT_ID clientId) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                bytes = 0;
    IONTOPENPROCESS_ARGS args;
    args.ProcessHandle    = processHandle;
    args.DesiredAccess    = desiredAccess;
    args.ObjectAttributes = objectAttributes;
    args.ClientId         = clientId;
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTOPENPROCESS, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtSuspendProcess(HANDLE processHandle) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                   bytes = 0;
    IONTSUSPENDPROCESS_ARGS args;
    args.ProcessHandle = processHandle;
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTSUSPENDPROCESS, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtResumeProcess(HANDLE processHandle) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                  bytes = 0;
    IONTRESUMEPROCESS_ARGS args;
    args.ProcessHandle = processHandle;
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTRESUMEPROCESS, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID inputBuffer,
                                                     ULONG inputBufferLength, PVOID systemInformation,
                                                     ULONG systemInformationLength, PULONG returnLength) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                             bytes = 0;
    IONTQUERYSYSTEMINFORMATIONEX_ARGS args;
    args.SystemInformationClass  = systemInformationClass;
    args.InputBuffer             = inputBuffer;
    args.InputBufferLength       = inputBufferLength;
    args.SystemInformation       = systemInformation;
    args.SystemInformationLength = systemInformationLength;
    args.ReturnLength            = returnLength;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTQUERYSYSTEMINFORMATIONEX, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtQueryInformationProcess(HANDLE processHandle, PROCESSINFOCLASS processInformationClass,
                                                    PVOID processInformation, ULONG processInformationLength,
                                                    PULONG returnLength) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                            bytes = 0;
    IONTQUERYINFORMATIONPROCESS_ARGS args;
    args.ProcessHandle            = processHandle;
    args.ProcessInformationClass  = (PROCESS_INFORMATION_CLASS)processInformationClass;
    args.ProcessInformation       = processInformation;
    args.ProcessInformationLength = processInformationLength;
    args.ReturnLength             = returnLength;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTQUERYINFORMATIONPROCESS, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return STATUS_SUCCESS;
}

NTSTATUS DriverControl::IONtSetInformationProcess(HANDLE processHandle, PROCESSINFOCLASS processInformationClass,
                                                  PVOID processInformation, ULONG processInformationLength) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                          bytes = 0;
    IONTSETINFORMATIONPROCESS_ARGS args;
    args.ProcessHandle            = processHandle;
    args.ProcessInformationClass  = processInformationClass;
    args.ProcessInformation       = processInformation;
    args.ProcessInformationLength = processInformationLength;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTSETINFORMATIONPROCESS, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtFlushInstructionCache(HANDLE processHandle, PVOID baseAddress, ULONG numberOfBytesToFlush) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                          bytes = 0;
    IONTFLUSHINSTRUCTIONCACHE_ARGS args;
    args.ProcessHandle        = processHandle;
    args.BaseAddress          = baseAddress;
    args.NumberOfBytesToFlush = numberOfBytesToFlush;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTFLUSHINSTRUCTIONCACHE, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtAllocateVirtualMemory(HANDLE processHandle, PVOID *baseAddress, SIZE_T zeroBits,
                                                  PULONG64 regionSize, ULONG allocationType, ULONG protect) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                          bytes = 0;
    IONTALLOCATEVIRTUALMEMORY_ARGS args;
    args.ProcessHandle  = processHandle;
    args.BaseAddress    = baseAddress;
    args.ZeroBits       = zeroBits;
    args.RegionSize     = regionSize;
    args.AllocationType = allocationType;
    args.Protect        = protect;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTALLOCATEVIRTUALMEMORY, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtFlushVirtualMemory(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize,
                                               PIO_STATUS_BLOCK ioStatus) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                       bytes = 0;
    IONTFLUSHVIRTUALMEMORY_ARGS args;
    args.ProcessHandle = processHandle;
    args.BaseAddress   = baseAddress;
    args.RegionSize    = regionSize;
    args.IoStatus      = ioStatus;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTFLUSHVIRTUALMEMORY, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtFreeVirtualMemory(HANDLE processHandle, PVOID *baseAddress, PULONG64 regionSize, ULONG freeType) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                      bytes = 0;
    IONTFREEVIRTUALMEMORY_ARGS args;
    args.ProcessHandle = processHandle;
    args.BaseAddress   = baseAddress;
    args.RegionSize    = regionSize;
    args.FreeType      = freeType;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTFREEVIRTUALMEMORY, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtLockVirtualMemory(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                      bytes = 0;
    IONTLOCKVIRTUALMEMORY_ARGS args;
    args.ProcessHandle = processHandle;
    args.BaseAddress   = baseAddress;
    args.RegionSize    = regionSize;
    args.LockOption    = lockOption;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTLOCKVIRTUALMEMORY, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtUnlockVirtualMemory(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                        bytes = 0;
    IONTUNLOCKVIRTUALMEMORY_ARGS args;
    args.ProcessHandle = processHandle;
    args.BaseAddress   = baseAddress;
    args.RegionSize    = regionSize;
    args.LockOption    = lockOption;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTUNLOCKVIRTUALMEMORY, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtProtectVirtualMemory(HANDLE processHandle, PVOID* baseAddress, PULONG64 regionSize,
                                                 ULONG newAccessProtection, PULONG oldAccessProtection) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                         bytes = 0;
    IONTPROTECTVIRTUALMEMORY_ARGS args;
    args.ProcessHandle       = processHandle;
    args.BaseAddress         = baseAddress;
    args.RegionSize          = regionSize;
    args.NewAccessProtection = newAccessProtection;
    args.OldAccessProtection = oldAccessProtection;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTPROTECTVIRTUALMEMORY, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtReadVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToRead,
                                              PSIZE_T numberOfBytesRead) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                      bytes = 0;
    IONTREADVIRTUALMEMORY_ARGS args;
    args.ProcessHandle       = processHandle;
    args.BaseAddress         = baseAddress;
    args.Buffer              = buffer;
    args.NumberOfBytesToRead = numberOfBytesToRead;
    args.NumberOfBytesRead   = numberOfBytesRead;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTREADVIRTUALMEMORY, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtWriteVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID buffer,
                                               SIZE_T numberOfBytesToWrite, PSIZE_T numberOfBytesWritten) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                       bytes = 0;
    IONTWRITEVIRTUALMEMORY_ARGS args;
    args.ProcessHandle        = processHandle;
    args.BaseAddress          = baseAddress;
    args.Buffer               = buffer;
    args.NumberOfBytesToWrite = numberOfBytesToWrite;
    args.NumberOfBytesWritten = numberOfBytesWritten;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTWRITEVIRTUALMEMORY, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtQueryVirtualMemory(HANDLE processHandle, PVOID baseAddress,
                                               MEMORY_INFORMATION_CLASS memoryInformationClass, PVOID memoryInformation,
                                               SIZE_T memoryInformationLength, PSIZE_T returnLength) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                       bytes = 0;
    IONTQUERYVIRTUALMEMORY_ARGS args;
    args.ProcessHandle           = processHandle;
    args.BaseAddress             = baseAddress;
    args.MemoryInformationClass  = memoryInformationClass;
    args.MemoryInformation       = memoryInformation;
    args.MemoryInformationLength = memoryInformationLength;
    args.ReturnLength            = returnLength;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTQUERYVIRTUALMEMORY, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtOpenThread(PHANDLE threadHandle, ACCESS_MASK accessMask, POBJECT_ATTRIBUTES objectAttributes,
                                       PCLIENT_ID clientId) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD               bytes = 0;
    IONTOPENTHREAD_ARGS args;
    args.ThreadHandle     = threadHandle;
    args.AccessMask       = accessMask;
    args.ObjectAttributes = objectAttributes;
    args.ClientId         = clientId;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTOPENTHREAD, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IoNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
                                           HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags,
                                           SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve,
                                           PVOID lpBytesBuffer) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                   bytes = 0;
    IONTCREATETHREADEX_ARGS args  = {hThread, DesiredAccess, ObjectAttributes,  ProcessHandle,      lpStartAddress, lpParameter,
                                     Flags,   StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer};

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTCREATETHREADEX, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    Sleep(1000);
    return status;
}

NTSTATUS DriverControl::IONtQueryInformationThread(HANDLE threadHandle, THREADINFOCLASS threadInformationClass,
                                                   PVOID threadInformation, ULONG threadInformationLength, PULONG returnLength) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                           bytes = 0;
    IONTQUERYINFORMATIONTHREAD_ARGS args;
    args.ThreadHandle            = threadHandle;
    args.ThreadInformationClass  = threadInformationClass;
    args.ThreadInformation       = threadInformation;
    args.ThreadInformationLength = threadInformationLength;
    args.ReturnLength            = returnLength;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTQUERYINFORMATIONTHREAD, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtSetInformationThread(HANDLE threadHandle, THREADINFOCLASS threadInformationClass,
                                                 PVOID threadInformation, ULONG threadInformationLength) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                         bytes = 0;
    IONTSETINFORMATIONTHREAD_ARGS args;
    args.ThreadHandle            = threadHandle;
    args.ThreadInformationClass  = threadInformationClass;
    args.ThreadInformation       = threadInformation;
    args.ThreadInformationLength = threadInformationLength;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTSETINFORMATIONTHREAD, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtGetContextThread(HANDLE threadHandle, PCONTEXT context) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                     bytes = 0;
    IONTGETCONTEXTTHREAD_ARGS args;
    args.ThreadHandle = threadHandle;
    args.Context      = context;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTGETCONTEXTTHREAD, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtSetContextThread(HANDLE threadHandle, PCONTEXT context) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                     bytes = 0;
    IONTSETCONTEXTTHREAD_ARGS args;
    args.ThreadHandle = threadHandle;
    args.Context      = context;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTSETCONTEXTTHREAD, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtResumeThread(HANDLE threadHandle, PULONG suspendCount) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                 bytes = 0;
    IONTRESUMETHREAD_ARGS args;
    args.ThreadHandle = threadHandle;
    args.SuspendCount = suspendCount;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTRESUMETHREAD, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtSuspendThread(HANDLE threadHandle, PULONG previousSuspendCount) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                  bytes = 0;
    IONTSUSPENDTHREAD_ARGS args;
    args.ThreadHandle         = threadHandle;
    args.PreviousSuspendCount = previousSuspendCount;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTSUSPENDTHREAD, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtWaitForSingleObject(HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                        bytes = 0;
    IONTWAITFORSINGLEOBJECT_ARGS args;
    args.Handle    = handle;
    args.Alertable = alertable;
    args.Timeout   = timeout;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTWAITFORSINGLEOBJECT, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

NTSTATUS DriverControl::IONtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
                                            PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
                                            ULONG Options) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    DWORD                    bytes = 0;
    IONTDUPLICATEOBJECT_ARGS args;
    args.SourceProcessHandle = SourceProcessHandle;
    args.SourceHandle        = SourceHandle;
    args.TargetProcessHandle = TargetProcessHandle;
    args.TargetHandle        = TargetHandle;
    args.DesiredAccess       = DesiredAccess;
    args.HandleAttributes    = HandleAttributes;
    args.Options             = Options;

    NTSTATUS status = STATUS_INVALID_HANDLE;
    DeviceIoControl(_hDriver, IOCTL_NTDUPLICATEOBJECT, &args, sizeof(args), &status, sizeof(status), &bytes, NULL);
    return status;
}

BOOL DriverControl::IOIsWow64Process(HANDLE hProcess, PBOOL Wow64Process) {
    if (_hDriver == INVALID_HANDLE_VALUE)
        return FALSE;
    DWORD                 bytes = 0;
    IOISWOW64PROCESS_ARGS args;
    args.hProcess     = hProcess;
    args.Wow64Process = Wow64Process;

    if (!DeviceIoControl(_hDriver, IOCTL_ISWOW64PROCESS, &args, sizeof(args), NULL, 0, &bytes, NULL)) {
        return FALSE;
    }
    return TRUE;
}


NTSTATUS
DriverControl::UnloadDriver(const std::wstring &svcName) {
    const wchar_t *szSvrName   = svcName.c_str();
    BOOL           bRet        = FALSE;
    SC_HANDLE      hServiceMgr = NULL; // SCM�������ľ��
    SC_HANDLE      hServiceDDK = NULL; // NT��������ķ�����
    SERVICE_STATUS SvrSta;
    // ��SCM������
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hServiceMgr == NULL) {
        // ����SCM������ʧ��
        bRet = FALSE;
        goto BeforeLeave;
    } else {
        // ����SCM������ʧ�ܳɹ�
    }
    // ����������Ӧ�ķ���
    hServiceDDK = OpenService(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);

    if (hServiceDDK == NULL) {
        // ����������Ӧ�ķ���ʧ��
        bRet = FALSE;
        goto BeforeLeave;
    } else {
    }
    // ֹͣ�����������ֹͣʧ�ܣ�ֻ�������������ܣ��ٶ�̬���ء�
    if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta)) {
    } else {
        // ����������Ӧ��ʧ��
    }
    // ��̬ж����������
    if (!DeleteService(hServiceDDK)) {
        // ж��ʧ��
    } else {
        // ж�سɹ�
    }
    bRet = TRUE;
BeforeLeave:
    // �뿪ǰ�رմ򿪵ľ��
    if (hServiceDDK) {
        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr) {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet ? STATUS_SUCCESS : LastNtStatus();
}
