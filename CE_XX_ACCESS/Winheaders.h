#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Shlwapi.h>
#include <TlHelp32.h>
#include <windows.h>
#include <winioctl.h>
// #include <winternl.h>
#include "ntdef.h"

#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)