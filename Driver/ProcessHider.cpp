#include "ProcessHider.h"
#include "Blocklist.h"

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#endif

EXTERN_C PUCHAR PsGetProcessImageFileName(PEPROCESS Process);

PVOID g_ObHandle = NULL;

OB_PREOP_CALLBACK_STATUS PreProcessCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    
    if (OperationInformation->ObjectType != PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
    PEPROCESS CallerProcess = IoGetCurrentProcess();

    if (TargetProcess == CallerProcess) {
        return OB_PREOP_SUCCESS;
    }

    
    UCHAR* processName = PsGetProcessImageFileName(TargetProcess);
    
    
    
    ANSI_STRING ansiName;
    UNICODE_STRING uniName;
    RtlInitAnsiString(&ansiName, (PCSZ)processName);
    if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniName, &ansiName, TRUE))) {
        
        if (ShouldFilterName(&uniName)) {
           
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
            } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
            }
        }
        RtlFreeUnicodeString(&uniName);
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterProcessHider(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    OB_OPERATION_REGISTRATION obOps[] = {
        {
            PsProcessType,
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            PreProcessCallback,
            NULL
        }
    };

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"388800");

    OB_CALLBACK_REGISTRATION obReg = {
        OB_FLT_REGISTRATION_VERSION,
        1,
        altitude,
        NULL,
        obOps
    };

    return ObRegisterCallbacks(&obReg, &g_ObHandle);
}

VOID UnregisterProcessHider()
{
    if (g_ObHandle) {
        ObUnRegisterCallbacks(g_ObHandle);
        g_ObHandle = NULL;
    }
}
