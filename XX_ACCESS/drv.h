#pragma once

#define NT_DEVICE_NAME  L"\\Device\\" XX_DEVICE_NAME
#define DOS_DEVICE_NAME L"\\DosDevices\\" XX_DEVICE_NAME

#define XX_POOL_TAG 'enoX'

NTSTATUS Dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);