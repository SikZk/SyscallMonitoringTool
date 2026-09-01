#pragma once
#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#define MAX_SYSCALL_NAME_LENGTH 32
#define MAX_PARAMETER_COUNT     12
#define NUMBER_OF_HOOKS         12

typedef struct _SYSCALL_TELEMETRY {
	CHAR SyscallName[MAX_SYSCALL_NAME_LENGTH];
	SIZE_T Timestamp;
	ULONG ProcessId;
	ULONG ThreadId;
	void* Caller;
	UCHAR NumberOfParameters;
	void* Parameters[MAX_PARAMETER_COUNT];
} SYSCALL_TELEMETRY, * PSYSCALL_TELEMETRY;

typedef struct _SYSCALL_LOG {
	OVERLAPPED        Overlapped;
	SYSCALL_TELEMETRY Telemetry;
} SYSCALL_LOG, * PSYSCALL_LOG;

EXTERN_C ULONG NtAllocateVirtualMemorySsn;

EXTERN_C void HookThunk();

EXTERN_C NTSTATUS NtAllocateVirtualMemoryThunk(
	HANDLE		ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR	ZeroBits,
	PSIZE_T		RegionSize,
	ULONG		AllocationType,
	ULONG		Protect
);

NTSTATUS NtAllocateVirtualMemoryHook(
	HANDLE		ProcessHandle,
	PVOID*		BaseAddress,
	ULONG_PTR	ZeroBits,
	PSIZE_T		RegionSize,
	ULONG		AllocationType,
	ULONG		Protect
);

BOOLEAN HookSyscall(
	PVOID	SyscallAddress,
	PUCHAR	PaddingAddress,
	ULONG	Index,
	ULONG* Ssn
);

