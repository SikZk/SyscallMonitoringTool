#pragma once
#include <Windows.h>

#define NtCurrentProcess ((HANDLE)(LONG_PTR)-1)

typedef struct _KNOWN_CALLBACKS
{
	PVOID KiUserExceptionDispatcher;
	PVOID LdrInitializeThunk;
	PVOID KiUserApcDispatcher;
	PVOID KiUserCallbackDispatcher;
} KNOWN_CALLBACKS, * PKNOWN_CALLBACKS;

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;  
	ULONG Reserved; 
	PVOID Callback; 
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;
#define REASON_UNBACKED_TARGET   0

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ ULONG ProcessInformationClass,
	_In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength
);

EXTERN_C VOID WINAPI PiCallback(_In_ PVOID OriginalTarget);

EXTERN_C VOID PiThunk();

void InitializePiCallback();