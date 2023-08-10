#pragma once
#pragma warning(disable:4996)

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#include "imports.h"

#include "def.h"
#include "drv.h"

#include "api.h"
#include "private.h"
#include "routines.h"
#include "utils.h"
#include "remote.h"
#include "apc.h"
#include "callbacks.h"
#include "protectProc.h"

#define LENGTH(a) (sizeof(a) / sizeof(a[0]))