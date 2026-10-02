#pragma once
#include <fltKernel.h>

FLT_PREOP_CALLBACK_STATUS JournalPreFsctl(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext);

FLT_POSTOP_CALLBACK_STATUS JournalPostFsctl(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags);
