#include "HideReg.h"
#include "Blocklist.h"

extern LARGE_INTEGER g_RegCookie; 


EXTERN_C NTSTATUS CmEnumerateKey(
    _In_ PVOID KeyControlBlock,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_opt_ PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
);

