#pragma once
#include "Utilities.h"
#include "WindowsUndocumentedKernelDefinitions.h"

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

BOOLEAN CanInjectIntoTheProcess(IN PEPROCESS Process) {
    if (Process == NULL)
        return FALSE;

    if (Process == PsInitialSystemProcess)
        return FALSE;

    if (PsIsProtectedProcess(Process))
        return FALSE;

	// TODO: add support for 32-bit processes
    if (IoIs32bitProcess(NULL))
        return FALSE;

    if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
        return FALSE;

    return TRUE;
}

SIZE_T RoundToHigherMultipleOf8(SIZE_T Value) {
    return (Value + 7) & ~(SIZE_T)7;
}