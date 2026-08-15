#pragma once
#include <ntifs.h>

extern "C" {

    typedef enum _KAPC_ENVIRONMENT
    {
        OriginalApcEnvironment,
        AttachedApcEnvironment,
        CurrentApcEnvironment,
        InsertApcEnvironment
    } KAPC_ENVIRONMENT;

    typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
        _In_opt_ PVOID NormalContext,
        _In_opt_ PVOID SystemArgument1,
        _In_opt_ PVOID SystemArgument2
    );

    typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
        _In_ PKAPC Apc,
        _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
        _Inout_ PVOID* NormalContext,
        _Inout_ PVOID* SystemArgument1,
        _Inout_ PVOID* SystemArgument2
    );

    typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(
        _In_ PKAPC Apc
    );

    NTKERNELAPI BOOLEAN NTAPI PsIsProtectedProcess(
        _In_ PEPROCESS
    );

    NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(
        _In_ PEPROCESS
    );

    NTKERNELAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
        _In_ HANDLE,
        _Inout_ PVOID*,
        _Inout_ PSIZE_T,
        _In_ ULONG,
        _Out_ PULONG
    );

    NTKERNELAPI VOID NTAPI KeInitializeApc(
        _Out_ PRKAPC Apc,
        _In_ PKTHREAD Thread,
        _In_ KAPC_ENVIRONMENT Environment,
        _In_ PKKERNEL_ROUTINE KernelRoutine,
        _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
        _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
        _In_opt_ KPROCESSOR_MODE ApcMode,
        _In_opt_ PVOID NormalContext
    );

    NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
        _Inout_ PRKAPC Apc,
        _In_opt_ PVOID SystemArgument1,
        _In_opt_ PVOID SystemArgument2,
        _In_ KPRIORITY Increment
    );

    NTKERNELAPI BOOLEAN NTAPI KeTestAlertThread(
        _In_ KPROCESSOR_MODE AlertMode
    );

} 