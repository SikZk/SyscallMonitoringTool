#pragma once
#include "Utilities.h"
#include <ntifs.h>

extern CONST UNICODE_STRING ntdllPath;
extern CONST UNICODE_STRING kernel32Path;

extern CONST UNICODE_STRING ntdllKernelObjectPath;
extern CONST UNICODE_STRING kernel32KernelObjectPath;

BOOLEAN IsImageNtdll(IN UNICODE_STRING* ImageName, IN IMAGE_INFO* ImageInfo);

BOOLEAN IsImageKernel32(IN UNICODE_STRING* ImageName, IN IMAGE_INFO* ImageInfo);

void* GetLdrLoadDllAddressFromNtdll(IN void* NtdllAddress);