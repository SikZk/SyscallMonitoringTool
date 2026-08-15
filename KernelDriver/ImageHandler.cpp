#pragma once
#include "ImageHandler.h"

CONST UNICODE_STRING ntdllPath = RTL_CONSTANT_STRING(L"\\Windows\\System32\\ntdll.dll");
CONST UNICODE_STRING kernel32Path = RTL_CONSTANT_STRING(L"\\Windows\\System32\\kernel32.dll");

CONST UNICODE_STRING ntdllKernelObjectPath = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
CONST UNICODE_STRING kernel32KernelObjectPath = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\kernel32.dll");

BOOLEAN IsImageNtdll(IN UNICODE_STRING* ImageName, IN IMAGE_INFO* ImageInfo) {
	UNREFERENCED_PARAMETER(ImageInfo);

	if (!CompareStringSuffix(ImageName, &ntdllPath)) {
		return FALSE;
	}
	// TODO: Implement more reliable checks, compare VolumeSerialNumber
	return TRUE;
}

BOOLEAN IsImageKernel32(IN UNICODE_STRING* ImageName, IN IMAGE_INFO* ImageInfo) {
	UNREFERENCED_PARAMETER(ImageInfo);
	if (!CompareStringSuffix(ImageName, &kernel32Path)) {
		return FALSE;
	}

	// TODO: Implement more reliable checks, compare VolumeSerialNumber
	return TRUE;
}

void* GetLdrLoadDllAddressFromNtdll(IN void* NtdllAddress) {

}