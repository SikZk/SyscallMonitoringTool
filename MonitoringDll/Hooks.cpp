#include "Hooks.h"
#include "Ntapi.h"

EXTERN_C PVOID  HookTable[NUMBER_OF_HOOKS] = { NtAllocateVirtualMemoryHook, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
EXTERN_C ULONG NtAllocateVirtualMemorySsn = 0;

extern PVOID  NtdllAddress;
extern ULONG  NtdllSize;
extern HANDLE PipeHandle;

NTSTATUS NtAllocateVirtualMemoryHook(
	HANDLE		ProcessHandle,
	PVOID*		BaseAddress,
	ULONG_PTR	ZeroBits,
	PSIZE_T		RegionSize,
	ULONG		AllocationType,
	ULONG		PageProtection
) {
	NTSTATUS Status;

	Status = NtAllocateVirtualMemoryThunk(
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		RegionSize,
		AllocationType,
		PageProtection
	);
	
	if (ProcessHandle == NtCurrentProcess && !(PageProtection & PAGE_EXECUTE)) {
		return Status;
	}
	if ((PUCHAR)_ReturnAddress() - (PUCHAR)NtdllAddress < NtdllSize) {
		return Status;
	}

	PSYSCALL_LOG Log = (PSYSCALL_LOG)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(SYSCALL_LOG)
	);

	if (Log == nullptr) {
		return Status;
	}

	PSYSCALL_TELEMETRY Telemetry = &Log->Telemetry;
	memcpy(Telemetry->SyscallName, "NtAllocateVirtualMemory", sizeof("NtAllocateVirtualMemory"));
	Telemetry->ProcessId = GetCurrentProcessId();
	Telemetry->ThreadId = GetCurrentThreadId();
	Telemetry->NumberOfParameters = 6;
	Telemetry->Parameters[0] = ProcessHandle;

	if (BaseAddress != 0) {
		Telemetry->Parameters[1] = *BaseAddress;
	}

	Telemetry->Parameters[2] = (PVOID)ZeroBits;

	if (RegionSize != 0) {
		Telemetry->Parameters[3] = (PVOID)*RegionSize;
	}

	Telemetry->Parameters[4] = (PVOID)AllocationType;
	Telemetry->Parameters[5] = (PVOID)PageProtection;
	Telemetry->Caller = _ReturnAddress();

	GetSystemTimePreciseAsFileTime((LPFILETIME)&Telemetry->Timestamp);


	ULONG BytesWritten;
	WriteFile(
		PipeHandle,
		Telemetry,
		sizeof(SYSCALL_TELEMETRY),
		&BytesWritten,
		&Log->Overlapped
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