#include <fltKernel.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#include "Prefetch.h"
#include "Amcache.h"
#include "Journal.h"
#include "MFT.h"
#include "Overwrite.h"
#include "ProcessHider.h"

#pragma comment(lib, "fltmgr.lib")
#pragma warning(disable: 4100)
#pragma warning(disable: 4996)

PFLT_FILTER g_FilterHandle = NULL;


static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    
    { IRP_MJ_CREATE, 0, PrefetchPreCreate, NULL },

    
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, JournalPreFsctl, JournalPostFsctl },
    
    { IRP_MJ_OPERATION_END }
};

EXTERN_C NTSTATUS JournalFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);

    UnregisterAmcachePrevention();
    UnregisterProcessHider();
    CloseOverwritePort();

    if (g_FilterHandle) { 
        FltUnregisterFilter(g_FilterHandle); 
        g_FilterHandle = NULL; 
    }
    return STATUS_SUCCESS;
}

static const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION,
    0, NULL, Callbacks, JournalFilterUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    
    status = RegisterAmcachePrevention(DriverObject);
    RegisterProcessHider(DriverObject);
    if (!NT_SUCCESS(status)) {
        
    }

    
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        UnregisterAmcachePrevention();
    UnregisterProcessHider();
        return status;
    }

    status = InitializeOverwritePort(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        UnregisterAmcachePrevention();
    UnregisterProcessHider();
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        UnregisterAmcachePrevention();
    UnregisterProcessHider();
        return status;
    }

    return STATUS_SUCCESS;
}
