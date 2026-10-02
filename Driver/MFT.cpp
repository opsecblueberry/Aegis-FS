#include "MFT.h"

NTSTATUS TimestompTargetFile(PCWSTR targetPath)
{
    NTSTATUS status;
    HANDLE hTarget = NULL;
    IO_STATUS_BLOCK ioStatus = {0};

    UNICODE_STRING uTarget;
    OBJECT_ATTRIBUTES oaTarget;
    RtlInitUnicodeString(&uTarget, targetPath);
    InitializeObjectAttributes(&oaTarget, &uTarget,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&hTarget,
        FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        &oaTarget, &ioStatus, NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    if (NT_SUCCESS(status)) {
        FILE_BASIC_INFORMATION fbi;
        if (NT_SUCCESS(ZwQueryInformationFile(hTarget, &ioStatus, &fbi, sizeof(fbi), FileBasicInformation))) {
            
            fbi.LastWriteTime = fbi.CreationTime;
            fbi.LastAccessTime = fbi.CreationTime;
            fbi.ChangeTime = fbi.CreationTime;
            status = ZwSetInformationFile(hTarget, &ioStatus, &fbi, sizeof(fbi), FileBasicInformation);
        }
        ZwClose(hTarget);
    }
    return status;
}
