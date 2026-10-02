#pragma once
#include <ntifs.h>

NTSTATUS RegisterHideRegistry(PDRIVER_OBJECT DriverObject);
VOID UnregisterHideRegistry();
