#include "Apc.h"
#include "Utilities.h"

static CONST UCHAR ShellcodeForApcInjection[] = {
    0x48, 0xB8,                                     /* mov rax, imm64       */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* <LdrLoadDll addr>    */
    0x48, 0x83, 0xEC, 0x28,                         /* sub rsp, 0x28        */
    0x49, 0x89, 0xC8,                               /* mov r8,  rcx         */
    0x4C, 0x8D, 0x4C, 0x24, 0x20,                   /* lea r9,  [rsp+0x20]  */
    0x48, 0x31, 0xC9,                               /* xor rcx, rcx         */
    0x48, 0x31, 0xD2,                               /* xor rdx, rdx         */
    0xFF, 0xD0,                                     /* call rax             */
    0x48, 0x83, 0xC4, 0x28,                         /* add rsp, 0x28        */
    0xC3                                            /* ret                  */
};

NTSTATUS InjectMonitoringDllViaApc(void* LdrLoadDllAddress) {
	void* LdrLoadDllAddressParams = nullptr;
	void* injectedMemoryAddress = WriteShellcodeIntoProcessMemory(LdrLoadDllAddress, &LdrLoadDllAddressParams);
	if (injectedMemoryAddress == nullptr) {
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS status = ScheduleApcToRunInUserMode(injectedMemoryAddress, (UNICODE_STRING*)LdrLoadDllAddressParams);
	if (!NT_SUCCESS(status)) {
		return status;
	}

    return STATUS_SUCCESS;
}

void* WriteShellcodeIntoProcessMemory(IN void* LdrLoadDllAddress, OUT void** LdrLoadDllAddressParams) {
    CONST UNICODE_STRING* DllPath = &KernelDriverData->MonitoringDllPath;
    NTSTATUS Status;
    /*
		offset  size  contents
        ------  ----  --------------------------------------------------
        0x00      35  shellcode (patched with LdrLoadDll addr at +0x02)
        0x23       5  padding  <- ROUND8(35) = 40
        0x28      16  UNICODE_STRING { Length, MaximumLength, Buffer } Buffer = Base + 0x38
        0x38     ~120 L"C:\\Users\\...\\MonitoringDll.dll"
        0xB0       2  L'\0'
    */
    SIZE_T ShellcodeSize = sizeof(ShellcodeForApcInjection);
    SIZE_T UnicodeStringOffset = RoundToHigherMultipleOf8(ShellcodeSize);
	SIZE_T DllPathOffset = UnicodeStringOffset + sizeof(UNICODE_STRING);
    SIZE_T TotalSize = DllPathOffset + DllPath->Length + sizeof(WCHAR);
    SIZE_T RegionSize = TotalSize;

	void* AddressWithinProcessVirtualMemory = nullptr;

    Status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(),
        &AddressWithinProcessVirtualMemory,
        0,
        &RegionSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(Status))
        return nullptr;

    UNICODE_STRING* UnicodeStringInProcessVirtualMemory = 
        (UNICODE_STRING*)((PUCHAR)AddressWithinProcessVirtualMemory + UnicodeStringOffset);

	WCHAR* DllPathInProcessVirtualMemory =
		(WCHAR*)((UCHAR*)AddressWithinProcessVirtualMemory + DllPathOffset);

    __try {

        RtlCopyMemory(
            AddressWithinProcessVirtualMemory,
            ShellcodeForApcInjection,
            ShellcodeSize
        );
        RtlCopyMemory(
            (PUCHAR)AddressWithinProcessVirtualMemory + LDRLOADDLL_PATCH_OFFSET,
            &LdrLoadDllAddress,
            sizeof(PVOID)
        );
        RtlCopyMemory(
            DllPathInProcessVirtualMemory, 
            DllPath->Buffer,
            DllPath->Length
        );
		UnicodeStringInProcessVirtualMemory->Length = DllPath->Length;
        UnicodeStringInProcessVirtualMemory->MaximumLength = DllPath->Length + sizeof(WCHAR);
		UnicodeStringInProcessVirtualMemory->Buffer = DllPathInProcessVirtualMemory;
    } 
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        goto Cleanup;
    }

    void* ProtectedAddressWithinProcessVirtualMemory = AddressWithinProcessVirtualMemory;
    SIZE_T ProtectedTotalSize = TotalSize;
    ULONG  OldProtect = 0;

    Status = ZwProtectVirtualMemory(
        ZwCurrentProcess(),
        &ProtectedAddressWithinProcessVirtualMemory,
        &ProtectedTotalSize,
        PAGE_EXECUTE_READ,
        &OldProtect
    );

    if (!NT_SUCCESS(Status))
        goto Cleanup;
    *LdrLoadDllAddressParams = UnicodeStringInProcessVirtualMemory;
	return AddressWithinProcessVirtualMemory;

Cleanup:
    {
        SIZE_T Zero = 0;
        ZwFreeVirtualMemory(
            ZwCurrentProcess(),
            &AddressWithinProcessVirtualMemory,
            &Zero,
            MEM_RELEASE
        );
    }
    return nullptr;
}

NTSTATUS ScheduleApcToRunInUserMode(void* shellcodeAddress, UNICODE_STRING* DllPath) {
	NTSTATUS Status = STATUS_SUCCESS;

    PKAPC UserModeApcToRunDllInjectionShellcode = (PKAPC)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(KAPC),
        MY_POOL_TAG
    );
    if (UserModeApcToRunDllInjectionShellcode == nullptr) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    KeInitializeApc(
        UserModeApcToRunDllInjectionShellcode,
        KeGetCurrentThread(),
        OriginalApcEnvironment,
        ShellcodeApcKernelRoutine,
        ApcInjectionRundownRoutine,
        (PKNORMAL_ROUTINE)shellcodeAddress,
        UserMode,
        DllPath
    );

    if (!KeInsertQueueApc(UserModeApcToRunDllInjectionShellcode, nullptr, nullptr, IO_NO_INCREMENT)) {
        ExFreePool2(
            UserModeApcToRunDllInjectionShellcode,
            MY_POOL_TAG,
            nullptr,
            0
        );
        Status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    goto Cleanup;

Cleanup:
    {
        SIZE_T Zero = 0;
        ZwFreeVirtualMemory(
            ZwCurrentProcess(),
            &shellcodeAddress,
            &Zero,
            MEM_RELEASE
        );
    }
	return Status;
}

void ShellcodeApcKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
) {
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (*NormalRoutine == NULL) {
        KdPrint(("[SyscallMonitoringTool] shellcode APC cancelled\n"));
    }
    ExFreePool2(
        Apc,
        MY_POOL_TAG,
        NULL,
        0
    );
}

void ApcInjectionRundownRoutine(_In_ PKAPC Apc) {
    ExFreePool2(
        Apc,
        MY_POOL_TAG,
        NULL,
        0
    );
}