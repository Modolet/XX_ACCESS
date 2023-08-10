#pragma once

NTSTATUS ProtectProcess(PPROTECT_PROCESS_INFO info);

NTSTATUS UnProtectProcess(PPROTECT_PROCESS_INFO info);

VOID CleanProtectProcess();
