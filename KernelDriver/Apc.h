#pragma once
#include <ntifs.h>
#include "KernelDriver.h"
#include "WindowsUndocumentedKernelDefinitions.h"

#define LDRLOADDLL_PATCH_OFFSET 2


// Returns a pointer to the allocated memory in the target process, or nullptr on failure.
void* WriteShellcodeIntoProcessMemory(IN void* LdrLoadDllAddress, OUT void** LdrLoadDllAddressParams);

NTSTATUS InjectMonitoringDllViaApc(void* LdrLoadDllAddress);

NTSTATUS ScheduleApcToRunInUserMode(void* shellcodeAddress, UNICODE_STRING* DllPath);

void PutThreadInAlertableWait(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

void ShellcodeApcKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

void ApcInjectionRundownRoutine(_In_ PKAPC Apc);