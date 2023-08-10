#include "pch.h"

VOID KernelApcInjectCallback(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1,
                             PVOID *SystemArgument2) {
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // DPRINT( "%s: Called. NormalRoutine = 0x%p\n", __FUNCTION__, *NormalRoutine );

    // Skip execution
    if (PsIsThreadTerminating(PsGetCurrentThread()))
        *NormalRoutine = NULL;

    // Fix Wow64 APC
    if (PsGetCurrentProcessWow64Process() != NULL)
        PsWrapApcWow64Thread(NormalContext, (PVOID *)NormalRoutine);

    ExFreePoolWithTag(Apc, XX_POOL_TAG);
}

VOID KernelApcPrepareCallback(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1,
                              PVOID *SystemArgument2) {
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // DPRINT( "%s: Called\n", __FUNCTION__ );

    // Alert current thread
    KeTestAlertThread(UserMode);
    ExFreePoolWithTag(Apc, XX_POOL_TAG);
}

NTSTATUS XXQueueUserApc(IN PETHREAD pThread, IN PVOID pUserFunc, IN PVOID Arg1, IN PVOID Arg2, IN PVOID Arg3, IN BOOLEAN bForce) {
    ASSERT(pThread != NULL);
    if (pThread == NULL)
        return STATUS_INVALID_PARAMETER;

    // Allocate APC
    PKAPC pPrepareApc = NULL;
    PKAPC pInjectApc  = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), XX_POOL_TAG);

    if (pInjectApc == NULL) {
        DPRINT("%s: Failed to allocate APC\n", __FUNCTION__);
        return STATUS_NO_MEMORY;
    }

    // Actual APC
    KeInitializeApc(pInjectApc, (PKTHREAD)pThread, OriginalApcEnvironment, &KernelApcInjectCallback, NULL,
                    (PKNORMAL_ROUTINE)(ULONG_PTR)pUserFunc, UserMode, Arg1);

    // Setup force-delivery APC
    if (bForce) {
        pPrepareApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), XX_POOL_TAG);
        KeInitializeApc(pPrepareApc, (PKTHREAD)pThread, OriginalApcEnvironment, &KernelApcPrepareCallback, NULL, NULL, KernelMode,
                        NULL);
    }

    // Insert APC
    if (KeInsertQueueApc(pInjectApc, Arg2, Arg3, 0)) {
        if (bForce && pPrepareApc)
            KeInsertQueueApc(pPrepareApc, NULL, NULL, 0);

        return STATUS_SUCCESS;
    } else {
        DPRINT("%s: Failed to insert APC\n", __FUNCTION__);

        ExFreePoolWithTag(pInjectApc, XX_POOL_TAG);

        if (pPrepareApc)
            ExFreePoolWithTag(pPrepareApc, XX_POOL_TAG);

        return STATUS_NOT_CAPABLE;
    }
}
