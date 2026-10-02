#include "MemoryCleaner.h"
#include <ntstrsafe.h>



typedef struct _UNICODE_STRING_64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG  Pad;
    ULONG64 Buffer;
} UNICODE_STRING_64;

static BOOLEAN CaseInsensitiveWCompare(PCWSTR s1, PCWSTR s2, SIZE_T len) {
    SIZE_T i;
    for (i = 0; i < len; i++) {
        wchar_t c1 = s1[i], c2 = s2[i];
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
        if (c1 != c2) return FALSE;
    }
    return TRUE;
}


EXTERN_C PUCHAR PsGetProcessImageFileName(PEPROCESS Process);

PEPROCESS FindProcessByName(const char* processName)
{
    PEPROCESS Target = NULL;
    for (ULONG i = 4; i < 262144; i += 4) {
        PEPROCESS p;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)i, &p))) {
            UCHAR* name = PsGetProcessImageFileName(p);
            if (name && _stricmp((const char*)name, processName) == 0) {
                Target = p;
                break;
            }
            ObDereferenceObject(p);
        }
    }
    return Target;
}

// VAD REMAPPING
NTSTATUS ZeroStringInProcessVAD(PEPROCESS Process, PCWSTR TargetString)
{
    if (!Process || !TargetString) return STATUS_INVALID_PARAMETER;

    KAPC_STATE apcState;
    PVOID address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returnLength;
    SIZE_T targetLen = wcslen(TargetString);

    KeStackAttachProcess(Process, &apcState);

    while (NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), address, (MEMORY_INFORMATION_CLASS)0, &mbi, sizeof(mbi), &returnLength)))
    {
        BOOLEAN shouldScan = FALSE;
        if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)) {
            shouldScan = TRUE;
        }

        
        if (shouldScan && mbi.Protect != PAGE_NOACCESS && !(mbi.Protect & PAGE_GUARD) && mbi.RegionSize <= 64 * 1024 * 1024) 
        {
            PMDL pMdl = NULL;
            PVOID mappedAddr = NULL;
            BOOLEAN pagesLocked = FALSE;

            __try {
                
                pMdl = IoAllocateMdl(mbi.BaseAddress, (ULONG)mbi.RegionSize, FALSE, FALSE, NULL);
                if (pMdl) {
                    MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
                    pagesLocked = TRUE;
                    mappedAddr = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
                    
                    if (mappedAddr) {
                        UCHAR* pBuf = (UCHAR*)mappedAddr;
                        
                        // For ROT13 encryption (baby encryption from microsoft)
                        wchar_t rotTarget[260] = {0};
                        RtlCopyMemory(rotTarget, TargetString, targetLen * 2);
                        for (SIZE_T j = 0; j < targetLen; j++) {
                            wchar_t c = rotTarget[j];
                            if (c >= L'a' && c <= L'z') rotTarget[j] = (wchar_t)((c - L'a' + 13) % 26 + L'a');
                            else if (c >= L'A' && c <= L'Z') rotTarget[j] = (wchar_t)((c - L'A' + 13) % 26 + L'A');
                        }

                        
                        for (SIZE_T i = 0; i < mbi.RegionSize; i++) {
                            if (i + targetLen * 2 <= mbi.RegionSize) {
                                BOOLEAN matchLiteral = CaseInsensitiveWCompare((PCWSTR)(pBuf + i), TargetString, targetLen);
                                BOOLEAN matchRot13 = !matchLiteral && CaseInsensitiveWCompare((PCWSTR)(pBuf + i), rotTarget, targetLen);
                                
                                if (matchLiteral || matchRot13) {
                                    
                                    RtlSecureZeroMemory(pBuf + i, targetLen * 2);
                                    if (i >= 8) RtlSecureZeroMemory(pBuf + i - 8, 16); 
                                    i += targetLen * 2 - 1;
                                }
                            }
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                
            }

            
            __try {
                if (pMdl) {
                    if (mappedAddr) MmUnmapLockedPages(mappedAddr, pMdl);
                    if (pagesLocked) MmUnlockPages(pMdl);
                    IoFreeMdl(pMdl); 
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        address = (PVOID)((UCHAR*)mbi.BaseAddress + mbi.RegionSize);
    }

    KeUnstackDetachProcess(&apcState);
    return STATUS_SUCCESS;
}

NTSTATUS CleanProcessMemory(PCWSTR TargetString)
{
    const char* targets[] = { "lsass.exe", "csrss.exe", "svchost.exe" };
    
    for (int i = 0; i < 3; i++) {
        PEPROCESS p = FindProcessByName(targets[i]);
        if (p) {
            ZeroStringInProcessVAD(p, TargetString);
            ObDereferenceObject(p);
        }
    }

    return STATUS_SUCCESS;
}
