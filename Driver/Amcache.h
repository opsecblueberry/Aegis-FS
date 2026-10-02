#pragma once
#include <ntddk.h>

NTSTATUS RegisterAmcachePrevention(PDRIVER_OBJECT DriverObject);
VOID UnregisterAmcachePrevention();
