#pragma once
#include <ntifs.h>

BOOLEAN CompareStringSuffix(IN UNICODE_STRING* String, IN CONST UNICODE_STRING* Suffix);
BOOLEAN CanInjectIntoTheProcess(IN PEPROCESS Process);
SIZE_T RoundToHigherMultipleOf8(SIZE_T Value);
