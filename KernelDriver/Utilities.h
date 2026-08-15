#pragma once
#include <ntifs.h>

BOOLEAN CompareStringSuffix(IN UNICODE_STRING* String, IN CONST UNICODE_STRING* Suffix);