#include "pch.h"
#include "ssdt.h"

NTSTATUS(NTAPI *PsResumeThread)(PETHREAD Thread, PULONG PreviousCount)         = NULL;
NTSTATUS(NTAPI *PsSuspendThread)(PETHREAD Thread, PULONG PreviousSuspendCount) = NULL;

ULONG        gNtCreateThdExIndex     = 0;
ULONG        gNtProtectVirtualMemory = 0;
ULONG        gNtLockVirtualMemory    = 0;
ULONG        gNtUnlockVirtualMemory  = 0;
PVOID        gCallBackLowerHandle    = NULL;
PVOID        gCallBackUpperHandle    = NULL;
LIST_ENTRY   gProtProcHead;
FAST_MUTEX   gProtProcMutex;
DYNAMIC_DATA dynData;
BOOL         gSymbolicLinkCreated = FALSE;
BOOL         gDeviceCreated       = FALSE;
BOOL         gGlobalInited        = FALSE;

extern ULONG PreviousModeOffset;

EXTERN_C NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING registryPath);
EXTERN_C VOID     DriverUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS          InitDynData(IN OUT PDYNAMIC_DATA pData);
NTSTATUS          XXGetBuildNO(OUT PULONG pBuildNo);
NTSTATUS          XXInitCallbacks();

NTSTATUS XXGetBuildNO(OUT PULONG pBuildNo) {
    ASSERT(pBuildNo != NULL);
    if (pBuildNo == NULL)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS          status      = STATUS_SUCCESS;
    UNICODE_STRING    strRegKey   = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
    UNICODE_STRING    strRegValue = RTL_CONSTANT_STRING(L"BuildLabEx");
    UNICODE_STRING    strRegValue10 = RTL_CONSTANT_STRING(L"UBR");
    UNICODE_STRING    strVerVal     = {0};
    HANDLE            hKey          = NULL;
    OBJECT_ATTRIBUTES keyAttr       = {0};

    InitializeObjectAttributes(&keyAttr, &strRegKey, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &keyAttr);
    if (NT_SUCCESS(status)) {
        PKEY_VALUE_FULL_INFORMATION pValueInfo =
            (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, XX_POOL_TAG);
        ULONG bytes = 0;

        if (pValueInfo) {
            // Try query UBR value
            status = ZwQueryValueKey(hKey, &strRegValue10, KeyValueFullInformation, pValueInfo, PAGE_SIZE, &bytes);
            if (NT_SUCCESS(status)) {
                *pBuildNo = *(PULONG)((PUCHAR)pValueInfo + pValueInfo->DataOffset);
                goto skip1;
            }

            status = ZwQueryValueKey(hKey, &strRegValue, KeyValueFullInformation, pValueInfo, PAGE_SIZE, &bytes);
            if (NT_SUCCESS(status)) {
                PWCHAR pData = (PWCHAR)((PUCHAR)pValueInfo->Name + pValueInfo->NameLength);
                for (ULONG i = 0; i < pValueInfo->DataLength; i++) {
                    if (pData[i] == L'.') {
                        for (ULONG j = i + 1; j < pValueInfo->DataLength; j++) {
                            if (pData[j] == L'.') {
                                strVerVal.Buffer = &pData[i] + 1;
                                strVerVal.Length = strVerVal.MaximumLength = (USHORT)((j - i) * sizeof(WCHAR));
                                status                                     = RtlUnicodeStringToInteger(&strVerVal, 10, pBuildNo);

                                goto skip1;
                            }
                        }
                    }
                }

            skip1:;
            }

            ExFreePoolWithTag(pValueInfo, XX_POOL_TAG);
        } else
            status = STATUS_NO_MEMORY;

        ZwClose(hKey);
    } else
        DPRINT("BlackBone: %s: ZwOpenKey failed with status 0x%X\n", __FUNCTION__, status);

    return status;
}

NTSTATUS XXInitGlobal() {
    NTSTATUS status = InitDynData(&dynData);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    InitializeListHead(&gProtProcHead);
    ExInitializeFastMutex(&gProtProcMutex);
    gGlobalInited = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS XXFreeGlobal() {
    while (!IsListEmpty(&gProtProcHead))
        ExFreePoolWithTag(RemoveHeadList(&gProtProcHead), XX_POOL_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS InitDynData(IN OUT PDYNAMIC_DATA pData) {
    NTSTATUS             status  = STATUS_SUCCESS;
    RTL_OSVERSIONINFOEXW verInfo = {0};

    if (pData == NULL)
        return STATUS_INVALID_ADDRESS;

    RtlZeroMemory(pData, sizeof(DYNAMIC_DATA));
    verInfo.dwOSVersionInfoSize = sizeof(verInfo);
    status                      = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

    if (status == STATUS_SUCCESS) {
        ULONG ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;
        pData->ver      = (WinVer)ver_short;
        status          = XXGetBuildNO(&pData->buildNo);
        DPRINT("OS version %d.%d.%d.%d.%d - 0x%x\n", verInfo.dwMajorVersion, verInfo.dwMinorVersion, verInfo.dwBuildNumber,
               verInfo.wServicePackMajor, pData->buildNo, ver_short);
        switch (ver_short) {
        case WINVER_7:
        case WINVER_7_SP1: {
            DPRINT("WIN7 & WIN7_SP1");
            PreviousModeOffset        = 0x1f6;
            pData->Protection         = 0x43C; // Bitfield, bit index - 0xB
            pData->UniqueProcessId    = 0x180;
            pData->ActiveProcessLinks = 0x188;
        } break;
        case WINVER_8: {
            DPRINT("WIN8");
            pData->Protection         = 0x648;
            pData->UniqueProcessId    = 0x2e0;
            pData->ActiveProcessLinks = 0x2e8;
        }

        break;
        case WINVER_81: {
            DPRINT("WIN8.1");
            pData->Protection         = 0x67A;
            pData->EProcessFlags2     = 0x2F8;
            pData->UniqueProcessId    = 0x2e0;
            pData->ActiveProcessLinks = 0x2e8;
        }

        break;
        case WINVER_10: {
            DPRINT("WIN10");
            switch (verInfo.dwBuildNumber) {
            case 10240:
                pData->Protection         = 0x6AA;
                pData->EProcessFlags2     = 0x300;
                pData->UniqueProcessId    = 0x2e0;
                pData->ActiveProcessLinks = 0x2e8;
                break;
            case 10586:
                pData->Protection         = 0x6B2;
                pData->EProcessFlags2     = 0x300;
                pData->UniqueProcessId    = 0x2e0;
                pData->ActiveProcessLinks = 0x2e8;
                break;
            case 14393:
                pData->Protection         = pData->buildNo >= 447 ? 0x6CA : 0x6C2;
                pData->EProcessFlags2     = 0x300;
                pData->UniqueProcessId    = 0x2e0;
                pData->ActiveProcessLinks = 0x2e8;
                break;
            case 15063:
                pData->Protection         = 0x6CA;
                pData->EProcessFlags2     = 0x300;
                pData->UniqueProcessId    = 0x2e0;
                pData->ActiveProcessLinks = 0x2e8;
                break;
            case 16299:
                pData->Protection         = 0x6CA;
                pData->EProcessFlags2     = 0x828; // MitigationFlags offset
                pData->UniqueProcessId    = 0x2e0;
                pData->ActiveProcessLinks = 0x2e8;
                break;
            case 17134:
                pData->Protection         = 0x6CA;
                pData->EProcessFlags2     = 0x828; // MitigationFlags offset
                pData->UniqueProcessId    = 0x2e0;
                pData->ActiveProcessLinks = 0x2e8;
                break;
            case 17763:
                pData->Protection             = 0x6CA;
                pData->EProcessFlags2         = 0x820; // MitigationFlags offset
                pData->UniqueProcessId        = 0x2e0;
                pData->ActiveProcessLinks     = 0x2e8;
                pData->EProcessThreadListHead = 0x488;
                pData->EThreadThreadListHead  = 0x6A8;
                pData->KThreadProcess         = 0x220;
                break;
            case 18362:
            case 18363:
                pData->Protection         = 0x6FA;
                pData->EProcessFlags2     = 0x850; // MitigationFlags offset
                pData->UniqueProcessId    = 0x2e0;
                pData->ActiveProcessLinks = 0x2e8;
                break;
            case 19041:
                pData->Protection         = 0x87A;
                pData->EProcessFlags2     = 0x9D4; // MitigationFlags offset
                pData->UniqueProcessId    = 0x440;
                pData->ActiveProcessLinks = 0x448;
                break;
            case 22000:
                pData->Protection         = 0x87A;
                pData->EProcessFlags2     = 0x9D4; // MitigationFlags offset
                pData->UniqueProcessId    = 0x440;
                pData->ActiveProcessLinks = 0x448;
                break;
            case 22621:
                pData->Protection         = 0x87A;
                pData->EProcessFlags2     = 0x9D4; // MitigationFlags offset
                pData->UniqueProcessId    = 0x440;
                pData->ActiveProcessLinks = 0x448;
                break;
            default:
                return STATUS_NOT_SUPPORTED;
            }
        } break;
        default:
            return STATUS_NOT_SUPPORTED;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS XXInitCallbacks() {
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(XXProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DPRINT("进程回调注册失败");
        return status;
    }
    OB_OPERATION_REGISTRATION operationUpper[2] = {
        {PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, pobUpperPreOperationCallBack},
        {PsThreadType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, pobUpperPreOperationCallBack},
    };
    OB_OPERATION_REGISTRATION operationLower[2] = {
        {PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, pobLowerPreOperationCallBack},
        {PsThreadType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, pobLowerPreOperationCallBack},
    };

    OB_CALLBACK_REGISTRATION obUpper = {OB_FLT_REGISTRATION_VERSION, 2, RTL_CONSTANT_STRING(L"410000"), NULL, operationUpper};
    OB_CALLBACK_REGISTRATION obLower = {OB_FLT_REGISTRATION_VERSION, 2, RTL_CONSTANT_STRING(L"110000"), NULL, operationLower};

    status = ObRegisterCallbacks(&obUpper, &gCallBackUpperHandle);
    if (!NT_SUCCESS(status)) {
        DPRINT("高位回调注册失败");
        goto Exit0;
    }
    status = ObRegisterCallbacks(&obLower, &gCallBackLowerHandle);
    if (!NT_SUCCESS(status)) {
        DPRINT("低位回调注册失败");
        goto Exit1;
    }
    return status;

Exit1:
    ObUnRegisterCallbacks(gCallBackUpperHandle);
    gCallBackUpperHandle = NULL;
Exit0:
    PsSetCreateProcessNotifyRoutineEx(XXProcessNotify, TRUE);
    return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING registryPath) {
    NTSTATUS       status       = STATUS_SUCCESS;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING deviceLink;

    UNREFERENCED_PARAMETER(registryPath);
    DriverObject->DriverUnload = DriverUnload;

    PLDR_DATA ldr;
    ldr = (PLDR_DATA)DriverObject->DriverSection;
    ldr->Flags |= 0x20;
    status = XXInitGlobal();
    if (!NT_SUCCESS(status)) {
        DPRINT("初始化数据失败");
        return status;
    }

    status = XXInitCallbacks();
    if (!NT_SUCCESS(status)) {
        DPRINT("初始化回调失败");
        return status;
    }

    // 获取KTHREAD.PreviousMode偏移
    if (!PreviousModeOffset)
        PreviousModeOffset = *(PULONG)((PBYTE)ExGetPreviousMode + 0xC);
    if (PreviousModeOffset > 0x400) {
        DPRINT("! invalid PreviousModeOffset (%x) !", PreviousModeOffset);
        status = STATUS_NOT_SUPPORTED;
        return status;
    }

    // NtSuspend/ResumeThread 未导出
    // UCHAR pattern1[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x48\x89\x4A\x40";
    // PVOID func;
    // status = XXSearchPattern(pattern1, 0xCC, sizeof(pattern1) - 1, (PCHAR)PsRegisterPicoProvider, 0x100, &func);
    //
    // if (!NT_SUCCESS(status)) {
    //     DPRINT("! failed to find \"PsResumeThread\"");
    //     return status;
    // }
    // *(PVOID *)&PsResumeThread = (PBYTE)func + *(PINT)((PBYTE)func + 3) + 7;
    //
    //
    // UCHAR pattern2[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x48\x89\x4A\x50";
    // status           = XXSearchPattern(pattern2, 0xCC, sizeof(pattern2) - 1, (PCHAR)func, 0x40, &func);
    // if (!NT_SUCCESS(status)) {
    //     DPRINT("! failed to find \"PsSuspendThead\"");
    //     return status;
    // }
    // *(PVOID *)&PsSuspendThread = (PBYTE)func + *(PINT)((PBYTE)func + 3) + 7;

    RtlUnicodeStringInit(&deviceName, NT_DEVICE_NAME);

    status = IoCreateDevice(DriverObject, 0, &deviceName, XX_FILE_DEVICE, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        DPRINT("%s: IoCreateDevice failed with status 0x%X", __FUNCTION__, status);
        return status;
    }
    gDeviceCreated                                         = TRUE;
    DriverObject->MajorFunction[IRP_MJ_CREATE]             = DriverObject->MajorFunction[IRP_MJ_CLOSE] =
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch;

    RtlUnicodeStringInit(&deviceLink, DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&deviceLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        DPRINT("%s: IoCreateSymbolicLink failed with status 0x%X", __FUNCTION__, status);
        IoDeleteDevice(deviceObject);
        return status;
    }
    gSymbolicLinkCreated = TRUE;

    UNICODE_STRING ustrDllFileName;
    RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
    gNtCreateThdExIndex     = SSDT::GetSSDTFunctionIndexAndAdd(ustrDllFileName, "NtCreateThreadEx");
    gNtProtectVirtualMemory = SSDT::GetSSDTFunctionIndexAndAdd(ustrDllFileName, "NtProtectVirtualMemory");
    gNtLockVirtualMemory    = SSDT::GetSSDTFunctionIndexAndAdd(ustrDllFileName, "NtLockVirtualMemory");
    gNtUnlockVirtualMemory  = SSDT::GetSSDTFunctionIndexAndAdd(ustrDllFileName, "NtUnlockVirtualMemory");

    return status;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {

    UNICODE_STRING deviceLinkUnicodeString;
    if (gCallBackUpperHandle) {
        ObUnRegisterCallbacks(gCallBackUpperHandle);
        gCallBackUpperHandle = NULL;
    }
    if (gCallBackLowerHandle) {
        ObUnRegisterCallbacks(gCallBackLowerHandle);
        gCallBackLowerHandle = NULL;
    }
    PsSetCreateProcessNotifyRoutineEx(XXProcessNotify, TRUE);

    RtlUnicodeStringInit(&deviceLinkUnicodeString, DOS_DEVICE_NAME);
    if (gSymbolicLinkCreated)
        IoDeleteSymbolicLink(&deviceLinkUnicodeString);
    if (gDeviceCreated)
        IoDeleteDevice(DriverObject->DeviceObject);
    if (gGlobalInited) {
        CleanProtectProcess();
        XXFreeGlobal();
    }
    return;
}
