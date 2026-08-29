#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

typedef NTSTATUS(NTAPI* PFN_NtAllocateVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID*      BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       Protect
    );

typedef NTSTATUS(NTAPI* PFN_NtFreeVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID*      BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       FreeType
    );

int main(void) {
    // Unbuffered, so nothing is lost if the process dies inside a hook.
    setvbuf(stdout, nullptr, _IONBF, 0);

    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    if (Ntdll == nullptr) {
        printf("[target] GetModuleHandleW(ntdll.dll) failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    PFN_NtAllocateVirtualMemory NtAllocateVirtualMemory =
        (PFN_NtAllocateVirtualMemory)GetProcAddress(Ntdll, "NtAllocateVirtualMemory");
    PFN_NtFreeVirtualMemory NtFreeVirtualMemory =
        (PFN_NtFreeVirtualMemory)GetProcAddress(Ntdll, "NtFreeVirtualMemory");

    if (NtAllocateVirtualMemory == nullptr || NtFreeVirtualMemory == nullptr) {
        printf("[target] GetProcAddress failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[target] pid=%lu  ntdll=%p\n", GetCurrentProcessId(), (void*)Ntdll);
    printf("[target] NtAllocateVirtualMemory=%p\n", (void*)NtAllocateVirtualMemory);
    printf("[target] NtFreeVirtualMemory=%p\n", (void*)NtFreeVirtualMemory);

    for (ULONG Iteration = 1;; Iteration++) {
        // Size cycles 0x1000..0x8000 so each hooked call is identifiable
        // and you can confirm the hook forwards RegionSize untouched.
        PVOID  BaseAddress = nullptr;
        SIZE_T RegionSize = (SIZE_T)((Iteration % 8) + 1) * 0x1000;

        printf("[target] #%lu calling NtAllocateVirtualMemory(RegionSize=0x%llX)...\n",
            Iteration, (unsigned long long)RegionSize);

        NTSTATUS Status = NtAllocateVirtualMemory(
            GetCurrentProcess(),
            &BaseAddress,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!NT_SUCCESS(Status)) {
            printf("[target] #%lu failed: 0x%08lX\n", Iteration, (unsigned long)Status);
        }
        else {
            printf("[target] #%lu ok: BaseAddress=%p RegionSize=0x%llX\n",
                Iteration, BaseAddress, (unsigned long long)RegionSize);

            PVOID  FreeBase = BaseAddress;
            SIZE_T FreeSize = 0;
            NtFreeVirtualMemory(GetCurrentProcess(), &FreeBase, &FreeSize, MEM_RELEASE);
        }

        printf("[target] waiting 5 seconds before repeating...\n");
        Sleep(5000);
    }

    return EXIT_SUCCESS;
}
