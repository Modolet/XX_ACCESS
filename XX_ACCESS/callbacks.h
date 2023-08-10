#pragma once

VOID XXProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

OB_PREOP_CALLBACK_STATUS pobLowerPreOperationCallBack(_In_ PVOID                            RegistrationContext,
                                                      _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);

OB_PREOP_CALLBACK_STATUS pobUpperPreOperationCallBack(_In_ PVOID                            RegistrationContext,
                                                      _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);