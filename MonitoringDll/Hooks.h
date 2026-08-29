#pragma once
#include <Windows.h>
#include <stdio.h>

#define NUMBER_OF_HOOKS         12

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

