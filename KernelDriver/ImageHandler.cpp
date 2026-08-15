#pragma once
#include "ImageHandler.h"
#include "WindowsUndocumentedKernelDefinitions.h"

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

void* GetLdrLoadDllAddressFromNtdll(IN void* NtdllAddress, IN IMAGE_INFO* ImageInfo) {
	void* ldrLoadDllAddress = nullptr;

	__try {
		void* ntHeadersAddress = (PUCHAR)NtdllAddress + ((PIMAGE_DOS_HEADER)NtdllAddress)->e_lfanew;
		PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ntHeadersAddress);
		
		void* exportDirAddress = (PUCHAR)NtdllAddress + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(exportDirAddress);

		void* namesAddress = (PUCHAR)NtdllAddress + exportDir->AddressOfNames;
		void* OrdinalsAddress = (PUCHAR)NtdllAddress + exportDir->AddressOfNameOrdinals;
		void* functionsAddress = (PUCHAR)NtdllAddress + exportDir->AddressOfFunctions;

		PULONG Names = (PULONG)(namesAddress);
		PUSHORT Ordinals = (PUSHORT)(OrdinalsAddress);
		PULONG Functions = (PULONG)(functionsAddress);
		ULONG  numberOfNames = exportDir->NumberOfNames;

		SIZE_T ImageSize = ImageInfo->ImageSize;

		for (ULONG i = 0; i < numberOfNames; i++) {

			ULONG NameOffsetFromImageBase = Names[i];
			if (NameOffsetFromImageBase >= ImageSize || ImageSize - NameOffsetFromImageBase < LDRLOADDLL_LEN + 1)
				continue;

			PCSTR Name = (PCSTR)((PUCHAR)NtdllAddress + NameOffsetFromImageBase);
			SIZE_T BytesThatMatch = RtlCompareMemory(Name, LDRLOADDLL_NAME, LDRLOADDLL_LEN + 1);
			if (BytesThatMatch != LDRLOADDLL_LEN + 1)
				continue;

			USHORT indexInFunctionsArray = Ordinals[i];
			if (indexInFunctionsArray >= exportDir->NumberOfFunctions)
				break;

			ldrLoadDllAddress = (PUCHAR)NtdllAddress + Functions[indexInFunctionsArray];
			break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KdPrint(("[SyscallMonitoringTool] Exception occurred while getting LdrLoadDll address\n"));
		ldrLoadDllAddress = nullptr;
	}

	return ldrLoadDllAddress;
}