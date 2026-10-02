#pragma once
#include <fltKernel.h>

FLT_PREOP_CALLBACK_STATUS PrefetchPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext);
