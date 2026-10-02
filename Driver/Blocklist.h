#pragma once
#include <ntddk.h>

#define FILTERED_ITEMS_COUNT 3

BOOLEAN CaseInsensitiveWCompare(PCWSTR s1, PCWSTR s2, SIZE_T len);
BOOLEAN ShouldFilterName(PCUNICODE_STRING Name);
