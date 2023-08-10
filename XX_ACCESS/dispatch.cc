#include "pch.h"

#define IHANDLE(_CODE, _FUNC, _IN)                                                                                               \
    case _CODE:                                                                                                                  \
        if (inputBufferLength >= sizeof(_IN) && ioBuffer) {                                                                      \
            auto buffer_args = *(_IN *)ioBuffer;                                                                                 \
            auto func_ret    = _FUNC(&buffer_args);                                                                              \
            if (outputBufferLength >= sizeof(func_ret) && ioBuffer) {                                                            \
                RtlCopyMemory(ioBuffer, &func_ret, sizeof(func_ret));                                                            \
                Irp->IoStatus.Information = sizeof(func_ret);                                                                    \
                status                    = STATUS_SUCCESS;                                                                      \
            }                                                                                                                    \
        } else {                                                                                                                 \
            status = STATUS_INFO_LENGTH_MISMATCH;                                                                                \
        }                                                                                                                        \
        break

#define IOHANDLE(_CODE, _FUNC, _IN, _OUT)                                                                                        \
    case _CODE: {                                                                                                                \
        if (inputBufferLength >= sizeof(_IN) && outputBufferLength >= sizeof(_OUT) && ioBuffer) {                                \
            _OUT result          = {0};                                                                                          \
            Irp->IoStatus.Status = _FUNC((_IN *)ioBuffer, &result);                                                              \
            RtlCopyMemory(ioBuffer, &result, sizeof(result));                                                                    \
            Irp->IoStatus.Information = sizeof(result);                                                                          \
        } else {                                                                                                                 \
            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;                                                                  \
        }                                                                                                                        \
    } break

NTSTATUS Dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS           status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack;
    PVOID              ioBuffer           = NULL;
    ULONG              inputBufferLength  = 0;
    ULONG              outputBufferLength = 0;
    ULONG              ioControlCode      = 0;
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    irpStack           = IoGetCurrentIrpStackLocation(Irp);
    ioBuffer           = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength  = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (irpStack->MajorFunction) {
    case IRP_MJ_DEVICE_CONTROL: {
        ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
        switch (ioControlCode) {
            IOHANDLE(IOCTL_PRINT, IOPrint, I_PRINT, O_PRINT);
            IOHANDLE(IOCTL_INJECTCODE, IOInjectCode, I_INJECT_CODE, O_INJECT_CODE);
            IHANDLE(IOCTL_SETPROTECTION, XXSetProtection, IO_SET_PROC_PROTECTION);
            IHANDLE(IOCTL_PROTECTPROC, XXProtectProcess, IO_PROTECT_PROC);
            IHANDLE(IOCTL_UNPROTECTPROC, XXUnProtectProcess, IO_PROTECT_PROC);
            /*** Process ***/
            IHANDLE(IOCTL_NTOPENPROCESS, XXIONTOpenProcess, IONTOPENPROCESS_ARGS);
            IHANDLE(IOCTL_NTSUSPENDPROCESS, XXIONTSuspendProcess, IONTSUSPENDPROCESS_ARGS);
            IHANDLE(IOCTL_NTRESUMEPROCESS, XXIONTResumeProcess, IONTRESUMEPROCESS_ARGS);
            IHANDLE(IOCTL_NTQUERYSYSTEMINFORMATIONEX, XXIONTQuerySystemInformationEx, IONTQUERYSYSTEMINFORMATIONEX_ARGS);
            IHANDLE(IOCTL_NTQUERYINFORMATIONPROCESS, XXIONTQueryInformationProcess, IONTQUERYINFORMATIONPROCESS_ARGS);
            IHANDLE(IOCTL_NTSETINFORMATIONPROCESS, XXIONTSetInformationProcess, IONTSETINFORMATIONPROCESS_ARGS);
            IHANDLE(IOCTL_NTFLUSHINSTRUCTIONCACHE, XXIONTFlushInstructionCache, IONTFLUSHINSTRUCTIONCACHE_ARGS);

            /*** Memory ***/
            IHANDLE(IOCTL_NTALLOCATEVIRTUALMEMORY, XXIONTAllocateVirtualMemory, IONTALLOCATEVIRTUALMEMORY_ARGS);
            IHANDLE(IOCTL_NTFLUSHVIRTUALMEMORY, XXIONTFlushVirtualMemory, IONTFLUSHVIRTUALMEMORY_ARGS);
            IHANDLE(IOCTL_NTFREEVIRTUALMEMORY, XXIONTFreeVirtualMemory, IONTFREEVIRTUALMEMORY_ARGS);
            IHANDLE(IOCTL_NTLOCKVIRTUALMEMORY, XXIONTLockVirtualMemory, IONTLOCKVIRTUALMEMORY_ARGS);
            IHANDLE(IOCTL_NTUNLOCKVIRTUALMEMORY, XXIONTUnlockVirtualMemory, IONTUNLOCKVIRTUALMEMORY_ARGS);
            IHANDLE(IOCTL_NTPROTECTVIRTUALMEMORY, XXIONTProtectVirtualMemory, IONTPROTECTVIRTUALMEMORY_ARGS);
            IHANDLE(IOCTL_NTREADVIRTUALMEMORY, XXIONTReadVirtualMemory, IONTREADVIRTUALMEMORY_ARGS);
            IHANDLE(IOCTL_NTWRITEVIRTUALMEMORY, XXIONTWriteVirtualMemory, IONTWRITEVIRTUALMEMORY_ARGS);
            IHANDLE(IOCTL_NTQUERYVIRTUALMEMORY, XXIONTQueryVirtualMemory, IONTQUERYVIRTUALMEMORY_ARGS);

            /*** Threads ***/
            IHANDLE(IOCTL_NTOPENTHREAD, XXIONTOpenThread, IONTOPENTHREAD_ARGS);
            IHANDLE(IOCTL_NTCREATETHREADEX, XXIONTCreateThreadEx, IONTCREATETHREADEX_ARGS);
            IHANDLE(IOCTL_NTQUERYINFORMATIONTHREAD, XXIONTQueryInformationThread, IONTQUERYINFORMATIONTHREAD_ARGS);
            IHANDLE(IOCTL_NTSETINFORMATIONTHREAD, XXIONTSetInformationThread, IONTSETINFORMATIONTHREAD_ARGS);
            IHANDLE(IOCTL_NTGETCONTEXTTHREAD, XXIONTGetContextThread, IONTGETCONTEXTTHREAD_ARGS);
            IHANDLE(IOCTL_NTSETCONTEXTTHREAD, XXIONTSetContextThread, IONTSETCONTEXTTHREAD_ARGS);
            IHANDLE(IOCTL_NTRESUMETHREAD, XXIONTResumeThread, IONTRESUMETHREAD_ARGS);
            IHANDLE(IOCTL_NTSUSPENDTHREAD, XXIONTSuspendThread, IONTSUSPENDTHREAD_ARGS);
            /*** Sync ***/
            IHANDLE(IOCTL_NTWAITFORSINGLEOBJECT, XXIONTWaitForSingleObject, IONTWAITFORSINGLEOBJECT_ARGS);
            /*** Handle ***/
            IHANDLE(IOCTL_NTDUPLICATEOBJECT, XXIONTDuplicateObject, IONTDUPLICATEOBJECT_ARGS);
            IHANDLE(IOCTL_ISWOW64PROCESS, XXIOIsWow64Process, IOISWOW64PROCESS_ARGS);
        default:
            break;
        }
    } break;
    default:
        break;
    }
    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}