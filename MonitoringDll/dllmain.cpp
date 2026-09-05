#include "dllmain.h"
#include "Hooks.h"
#include "Ntapi.h"

UCHAR PushRcxAndJmp[] = {
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x51,                                           /* push rcx             */
	0x48, 0xB8,                                     /* mov rax, imm64       */
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* <target address>     */
	0xFF, 0xE0                                      /* jmp rax              */
};

CONST UCHAR Padding[sizeof(PushRcxAndJmp)] = {
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, /* int3                 */
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, /* int3                 */
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC  /* int3                 */
};

PVOID  NtdllAddress;
ULONG  NtdllSize;
HANDLE PipeHandle;
HANDLE IocpHandle;

ULONG WINAPI IocpThread() {
	OVERLAPPED_ENTRY Entries[10] = { 0 };
	ULONG            EntriesRemoved = 0;

	while (GetQueuedCompletionStatusEx(IocpHandle, Entries, 10, &EntriesRemoved, INFINITE, FALSE))
	{
		for (ULONG Index = 0; Index < EntriesRemoved; Index++)
		{
			if (Entries[Index].lpOverlapped != 0)
			{
				HeapFree(GetProcessHeap(), 0, Entries[Index].lpOverlapped);
			}
		}
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		BOOLEAN CanConnect;

		CanConnect = WaitNamedPipeW(L"\\\\.\\pipe\\MonitoringService", 5 * 1000);
		if (CanConnect == FALSE) {
			break;
		}

		PipeHandle = CreateFileW(L"\\\\.\\pipe\\MonitoringService",
			FILE_WRITE_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			0,
			OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED,
			0
		);

		if (PipeHandle == INVALID_HANDLE_VALUE) {
			printf("[Dll] Could not connect to the service: %lu", GetLastError());
			break;
		}

		IocpHandle = CreateIoCompletionPort(PipeHandle, 0, 0, 0);
		if (IocpHandle == 0) {
			printf("[Dll] Could not create IOCP: %lu", GetLastError());
			CloseHandle(PipeHandle);
			break;
		}

		if (CreateThread(0, 0, (LPTHREAD_START_ROUTINE)IocpThread, 0, 0, 0) == FALSE) {
			CloseHandle(PipeHandle);
			CloseHandle(IocpHandle);
			printf("[Dll] Could not create worker thread: %lu", GetLastError());
			break;
		}

		InitializeSyscallHooks();
		
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

}

void InitializeSyscallHooks() {
    void* NtdllAddress = GetModuleHandleW(L"ntdll.dll");

	if (!NtdllAddress) {
		printf("[Dll] GetModuleHandleW could not find ntdll: %lu (WTF?)", GetLastError());
		return;
	}

	void* PaddingAddress = FindNtdllPadding(NtdllAddress);
	if (PaddingAddress == nullptr) {
		printf("[Dll] Could not find compiler padding of sufficient size in NTDLL");
		return;
	}

	*(PVOID*)(PushRcxAndJmp + 14) = HookThunk;

	printf("[Dll] NtdllAddress: %p, PaddingAddress: %p\n", NtdllAddress, PaddingAddress);

	SIZE_T  BytesWritten = 0;
	BOOLEAN Result;
	Result = WriteProcessMemory(
		GetCurrentProcess(),
		PaddingAddress,
		PushRcxAndJmp,
		sizeof(PushRcxAndJmp),
		&BytesWritten
	);

	if (Result == FALSE || BytesWritten != sizeof(PushRcxAndJmp))
	{
		printf("[Dll] Failed overwriting compiler padding using WPM: %lu", GetLastError());
		return;
	}

	HookSyscall(NtAllocateVirtualMemory, (PUCHAR)PaddingAddress, 0, &NtAllocateVirtualMemorySsn);
}

void* FindNtdllPadding(IN void* NtdllAddress) {
	void* ntHeadersAddress; 
	ULONG  NtdllSize;
	IMAGE_NT_HEADERS* NtHeaders;

	ntHeadersAddress = (PUCHAR)NtdllAddress + ((PIMAGE_DOS_HEADER)NtdllAddress)->e_lfanew;
	NtHeaders = (IMAGE_NT_HEADERS*)(ntHeadersAddress);
	NtdllSize = NtHeaders->OptionalHeader.SizeOfImage;

	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	PUCHAR                Code = 0;
	ULONG                 CodeSize = 0;

	for (int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
		if (memcmp(Section[i].Name, ".text\0\0\0", IMAGE_SIZEOF_SHORT_NAME) == 0) {
			Code = (PUCHAR)NtdllAddress + Section[i].VirtualAddress;
			CodeSize = Section[i].Misc.VirtualSize;
		}
	}

	if (Code == 0) {
		printf("[Dll] Could not find NTDLL's .text section");
		return nullptr;
	}

	PUCHAR Current;

	for (ULONG Index = 0; Index < CodeSize; Index++)
	{
		if (CodeSize - Index < sizeof(Padding))
		{
			break;
		}

		Current = Code + Index;

		if (memcmp(Current, Padding, sizeof(Padding)) == 0)
		{
			return Current;
		}
	}

	return nullptr;
}