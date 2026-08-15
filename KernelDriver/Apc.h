#pragma once
#include <ntifs.h>
#include "KernelDriver.h"
#include "WindowsUndocumentedKernelDefinitions.h"

#define LDRLOADDLL_PATCH_OFFSET 2

NTSTATUS InjectMonitoringDllWithApc(void* LdrLoadDllAddress);

void UserApcKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

void UserApcRundownRoutine(_In_ PKAPC Apc);