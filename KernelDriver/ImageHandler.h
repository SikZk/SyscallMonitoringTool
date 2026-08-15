#pragma once
#include "Utilities.h"
#include <ntifs.h>
#include <ntimage.h>
#include <ntddk.h>

#define LDRLOADDLL_NAME  "LdrLoadDll"
#define LDRLOADDLL_LEN   (sizeof(LDRLOADDLL_NAME) - 1)

extern CONST UNICODE_STRING ntdllPath;
extern CONST UNICODE_STRING kernel32Path;

extern CONST UNICODE_STRING ntdllKernelObjectPath;
extern CONST UNICODE_STRING kernel32KernelObjectPath;

BOOLEAN IsImageNtdll(IN UNICODE_STRING* ImageName, IN IMAGE_INFO* ImageInfo);

BOOLEAN IsImageKernel32(IN UNICODE_STRING* ImageName, IN IMAGE_INFO* ImageInfo);

void* GetLdrLoadDllAddressFromNtdll(IN void* NtdllAddress, IN IMAGE_INFO* ImageInfo);