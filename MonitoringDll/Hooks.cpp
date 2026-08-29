#include "Hooks.h"
#include "Ntapi.h"

EXTERN_C PVOID  HookTable[NUMBER_OF_HOOKS] = { NtAllocateVirtualMemoryHook, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
EXTERN_C ULONG NtAllocateVirtualMemorySsn = 0;

NTSTATUS NtAllocateVirtualMemoryHook(
	HANDLE		ProcessHandle,
	PVOID*		BaseAddress,
	ULONG_PTR	ZeroBits,
	PSIZE_T		RegionSize,
	ULONG		AllocationType,
	ULONG		Protect
) {
	NTSTATUS Status;

	printf("NtAllocateVirtualMemory called\n");
	
	Status = NtAllocateVirtualMemoryThunk(
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		RegionSize,
		AllocationType,
		Protect
	);

	return Status;
}

BOOLEAN HookSyscall(
	PVOID	SyscallAddress,
	PUCHAR	PaddingAddress,
	ULONG	Index,
	ULONG* Ssn
) {
	UCHAR  JmpInstr[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	PUCHAR Rip = (PUCHAR)(SyscallAddress)+0x8;
	LONG   Offset = (LONG)((PaddingAddress + NUMBER_OF_HOOKS - Index) - Rip);

	*(PULONG)(JmpInstr + 0x01) = Offset;

	*Ssn = *(PULONG)((PUCHAR)SyscallAddress + 0x04);
	
	return WriteProcessMemory(
		GetCurrentProcess(),
		(PUCHAR)SyscallAddress + 0x03,
		JmpInstr,
		sizeof(JmpInstr),
		nullptr
	);

}