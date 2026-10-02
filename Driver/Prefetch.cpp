#include "Prefetch.h"
#include "Blocklist.h"

FLT_PREOP_CALLBACK_STATUS PrefetchPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo;
    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) 
    {
        FltParseFileNameInformation(nameInfo);

        if (nameInfo->Extension.Length > 0 && 
            CaseInsensitiveWCompare(nameInfo->Extension.Buffer, L"pf", 2)) 
        {
            
            if (ShouldFilterName(&nameInfo->Name)) {
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                FltReleaseFileNameInformation(nameInfo);
                return FLT_PREOP_COMPLETE;
            }
        }
        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
