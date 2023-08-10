#pragma once

NTSTATUS XXQueueUserApc(IN PETHREAD pThread, IN PVOID pUserFunc, IN PVOID Arg1, IN PVOID Arg2, IN PVOID Arg3, IN BOOLEAN bForce);