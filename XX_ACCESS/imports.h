#pragma once
#include "enums.h"
#include "pestructs.h"
#include "structs.h"
#include "structs10.h"
#include "structs7.h"
#include "structs8.h"
#include "structs81.h"
EXTERN_C_START

typedef VOID HANDLE_TABLE, *PHANDLE_TABLE;

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID(NTAPI *PKKERNEL_ROUTINE)(PRKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1,
                                      PVOID *SystemArgument2);
typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(PRKAPC Apc);

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                                      PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                      PULONG ReturnLength);
NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                                    PVOID ProcessInformation, ULONG ProcessInformationLength);
NTSYSCALLAPI NTSTATUS NTAPI ZwFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
NTSYSCALLAPI NTSTATUS NTAPI ZwQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                                     PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
NTSYSCALLAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

NTKERNELAPI NTSTATUS NTAPI       PsSuspendProcess(HANDLE ProcessId);
NTKERNELAPI NTSTATUS NTAPI       PsResumeProcess(HANDLE ProcessId);
NTKERNELAPI NTSTATUS NTAPI       PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
NTKERNELAPI NTSTATUS NTAPI       PsLookupProcessThreadByCid(PCLIENT_ID ClientId, PEPROCESS *Process, PETHREAD *Thread);
NTKERNELAPI PPEB NTAPI           PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI HANDLE NTAPI         PsGetProcessInheritedFromUniqueProcessId(PEPROCESS Process);
NTKERNELAPI PVOID NTAPI          PsGetProcessWow64Process(PEPROCESS Process);
NTKERNELAPI NTSTATUS NTAPI       MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess,
                                                     PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
                                                     PSIZE_T ReturnSize);
NTKERNELAPI NTSTATUS NTAPI       PsGetContextThread(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);
NTKERNELAPI NTSTATUS NTAPI       PsSetContextThread(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);
NTKERNELAPI PVOID NTAPI          RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineName);
NTKERNELAPI PVOID NTAPI          PsRegisterPicoProvider(PVOID, PVOID);
NTKERNELAPI PVOID NTAPI          PsGetThreadTeb(PETHREAD Thread);
NTSYSCALLAPI NTSTATUS NTAPI      NtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer,
                                                            ULONG InputBufferLength, PVOID SystemInformation,
                                                            ULONG SystemInformationLength, PULONG ReturnLength);
NTKERNELAPI VOID NTAPI           KeInitializeApc(IN PKAPC Apc, IN PKTHREAD Thread, IN KAPC_ENVIRONMENT ApcStateIndex,
                                                 IN PKKERNEL_ROUTINE KernelRoutine, IN PKRUNDOWN_ROUTINE RundownRoutine,
                                                 IN PKNORMAL_ROUTINE NormalRoutine, IN KPROCESSOR_MODE ApcMode, IN PVOID NormalContext);
NTKERNELAPI BOOLEAN NTAPI        KeInsertQueueApc(PKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);
NTKERNELAPI PVOID NTAPI          PsGetCurrentProcessWow64Process();
NTKERNELAPI BOOLEAN NTAPI        KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);
NTKERNELAPI BOOLEAN NTAPI        PsIsProtectedProcess(IN PEPROCESS Process);
NTKERNELAPI UCHAR               *PsGetProcessImageFileName(PEPROCESS Process);
NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);


EXTERN_C_END