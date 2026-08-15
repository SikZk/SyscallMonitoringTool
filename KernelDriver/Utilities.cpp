#pragma once
#include "Utilities.h"

BOOLEAN CompareStringSuffix(IN UNICODE_STRING* String, IN CONST UNICODE_STRING* Suffix) {
    if (String->Length < Suffix->Length) {
        return FALSE;
    }

    UNICODE_STRING Temp;
    Temp.Length = Suffix->Length;
    Temp.MaximumLength = Suffix->Length;
    Temp.Buffer = (PWSTR)RtlOffsetToPointer(String->Buffer, String->Length - Suffix->Length);

    return RtlEqualUnicodeString(&Temp, Suffix, TRUE);
}