#include "Blocklist.h"
#define _KERNEL_MODE
#include "skCrypter.h"

BOOLEAN CaseInsensitiveWCompare(PCWSTR s1, PCWSTR s2, SIZE_T len) {
    SIZE_T i;
    for (i = 0; i < len; i++) {
        wchar_t c1 = s1[i], c2 = s2[i];
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
        if (c1 != c2) return FALSE;
    }
    return TRUE;
}

BOOLEAN ShouldFilterName(PCUNICODE_STRING Name) {
    if (!Name || !Name->Buffer || Name->Length == 0) return FALSE;
    USHORT nameLenChars = Name->Length / sizeof(WCHAR);

    auto item1 = skCrypt(L"CHEAT.EXE");
    auto item2 = skCrypt(L"CHEAT2.EXE");
    auto item3 = skCrypt(L"CHEAT3.EXE");

    PCWSTR runtimeFilteredItems[FILTERED_ITEMS_COUNT] = {
        item1.decrypt(),
        item2.decrypt(),
        item3.decrypt()
    };

    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < FILTERED_ITEMS_COUNT; i++) {
        PCWSTR target = runtimeFilteredItems[i];
        if (!target || target[0] == L'\0') continue;
        USHORT targetLen = 0;
        while (target[targetLen] != L'\0') targetLen++;
        if (targetLen > nameLenChars) continue;
        for (USHORT j = 0; j <= nameLenChars - targetLen; j++) {
            if (CaseInsensitiveWCompare(&Name->Buffer[j], target, targetLen)) {
                found = TRUE;
                break;
            }
        }
        if (found) break;
    }

    item1.encrypt();
    item2.encrypt();
    item3.encrypt();

    return found;
}
