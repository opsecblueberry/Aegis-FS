#pragma once
#include <ntifs.h>

NTSTATUS RegisterProcessHider(PDRIVER_OBJECT DriverObject);
VOID UnregisterProcessHider();
