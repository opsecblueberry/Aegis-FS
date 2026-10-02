#pragma once
#include <fltKernel.h>

NTSTATUS InitializeOverwritePort(PFLT_FILTER filterHandle);
VOID CloseOverwritePort();
