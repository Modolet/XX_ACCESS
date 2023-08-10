#pragma once
NTSTATUS IOPrint(PI_PRINT input, PO_PRINT result);

NTSTATUS XXSetProtection(IN PIO_SET_PROC_PROTECTION pProtection);

NTSTATUS XXProtectProcess(IN PIO_PROTECT_PROC pData);

NTSTATUS XXUnProtectProcess(IN PIO_PROTECT_PROC pData);