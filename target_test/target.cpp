#include <windows.h>
#include <winhttp.h>
#include <winldap.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

// winhttp.h and winldap.h are included for the prototypes only. The operand of
// decltype is unevaluated, so these do NOT reference the symbols and no import is
// generated. Do not add winhttp.lib or wldap32.lib to the linker: a static import
// would make the loader map those DLLs as part of this EXE import graph, before the
// monitoring DLL is injected, and the LdrRegisterDllNotification callback would
// never fire for them.
using PFN_WinHttpOpen        = decltype(&WinHttpOpen);
using PFN_WinHttpConnect     = decltype(&WinHttpConnect);
using PFN_WinHttpCloseHandle = decltype(&WinHttpCloseHandle);

using PFN_ldap_initW         = decltype(&ldap_initW);
using PFN_ldap_connect       = decltype(&ldap_connect);
using PFN_ldap_bind_sW       = decltype(&ldap_bind_sW);
using PFN_ldap_unbind        = decltype(&ldap_unbind);

static PFN_NtAllocateVirtualMemory NtAllocateVirtualMemory = nullptr;
static PFN_NtFreeVirtualMemory     NtFreeVirtualMemory     = nullptr;

static HMODULE                     WinHttpModule       = nullptr;
static PFN_WinHttpOpen             pWinHttpOpen        = nullptr;
static PFN_WinHttpConnect          pWinHttpConnect     = nullptr;
static PFN_WinHttpCloseHandle      pWinHttpCloseHandle = nullptr;

static HMODULE                     Wldap32Module       = nullptr;
static PFN_ldap_initW              pldap_initW         = nullptr;
static PFN_ldap_connect            pldap_connect       = nullptr;
static PFN_ldap_bind_sW            pldap_bind_sW       = nullptr;
static PFN_ldap_unbind             pldap_unbind        = nullptr;

// An unhooked NtAllocateVirtualMemory starts with 4C 8B D1 B8 <ssn>; once the syscall
// hook is in, byte +3 becomes E9 <rel32>. An unhooked WinHttpConnect starts with a
// normal prologue; Detours replaces the first bytes with E9 or FF 25. Dumping the
// first 16 bytes tells you at a glance whether the patch landed.
static void PrintFirstBytes(const char* Name, void* Address) {
    if (Address == nullptr) {
        printf("[target] %-24s not resolved\n", Name);
        return;
    }

    PUCHAR Bytes = (PUCHAR)Address;
    printf("[target] %-24s @ %p:", Name, Address);

    for (int Index = 0; Index < 16; Index++) {
        printf(" %02X", Bytes[Index]);
    }

    printf("\n");
}

static BOOL ResolveNtdll(void) {
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    if (Ntdll == nullptr) {
        printf("[target] GetModuleHandleW(ntdll.dll) failed: %lu\n", GetLastError());
        return FALSE;
    }

    NtAllocateVirtualMemory =
        (PFN_NtAllocateVirtualMemory)GetProcAddress(Ntdll, "NtAllocateVirtualMemory");
    NtFreeVirtualMemory =
        (PFN_NtFreeVirtualMemory)GetProcAddress(Ntdll, "NtFreeVirtualMemory");

    if (NtAllocateVirtualMemory == nullptr || NtFreeVirtualMemory == nullptr) {
        printf("[target] GetProcAddress on ntdll failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[target] pid=%lu  ntdll=%p\n", GetCurrentProcessId(), (void*)Ntdll);
    PrintFirstBytes("NtAllocateVirtualMemory", (void*)NtAllocateVirtualMemory);
    return TRUE;
}

// Loaded on demand, so the load happens well after the monitoring DLL has attached
// and registered its notification callback.
static BOOL LoadWinHttp(void) {
    if (WinHttpModule != nullptr) {
        return TRUE;
    }

    printf("[target] LoadLibraryW(winhttp.dll)...\n");

    WinHttpModule = LoadLibraryW(L"winhttp.dll");
    if (WinHttpModule == nullptr) {
        printf("[target] LoadLibraryW(winhttp.dll) failed: %lu\n", GetLastError());
        return FALSE;
    }

    pWinHttpOpen        = (PFN_WinHttpOpen)GetProcAddress(WinHttpModule, "WinHttpOpen");
    pWinHttpConnect     = (PFN_WinHttpConnect)GetProcAddress(WinHttpModule, "WinHttpConnect");
    pWinHttpCloseHandle = (PFN_WinHttpCloseHandle)GetProcAddress(WinHttpModule, "WinHttpCloseHandle");

    if (pWinHttpOpen == nullptr || pWinHttpConnect == nullptr || pWinHttpCloseHandle == nullptr) {
        printf("[target] GetProcAddress on winhttp failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[target] winhttp.dll=%p\n", (void*)WinHttpModule);
    PrintFirstBytes("WinHttpConnect", (void*)pWinHttpConnect);
    return TRUE;
}

static BOOL LoadWldap32(void) {
    if (Wldap32Module != nullptr) {
        return TRUE;
    }

    printf("[target] LoadLibraryW(wldap32.dll)...\n");

    Wldap32Module = LoadLibraryW(L"wldap32.dll");
    if (Wldap32Module == nullptr) {
        printf("[target] LoadLibraryW(wldap32.dll) failed: %lu\n", GetLastError());
        return FALSE;
    }

    pldap_initW   = (PFN_ldap_initW)GetProcAddress(Wldap32Module, "ldap_initW");
    pldap_connect = (PFN_ldap_connect)GetProcAddress(Wldap32Module, "ldap_connect");
    pldap_bind_sW = (PFN_ldap_bind_sW)GetProcAddress(Wldap32Module, "ldap_bind_sW");
    pldap_unbind  = (PFN_ldap_unbind)GetProcAddress(Wldap32Module, "ldap_unbind");

    if (pldap_initW == nullptr || pldap_connect == nullptr ||
        pldap_bind_sW == nullptr || pldap_unbind == nullptr) {
        printf("[target] GetProcAddress on wldap32 failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[target] wldap32.dll=%p\n", (void*)Wldap32Module);
    PrintFirstBytes("ldap_bind_sW", (void*)pldap_bind_sW);
    return TRUE;
}

static void CallNtAllocateVirtualMemory(ULONG Iteration) {
    // Size cycles 0x1000..0x8000 so each hooked call is identifiable and you can
    // confirm the hook forwards RegionSize untouched.
    PVOID  BaseAddress = nullptr;
    SIZE_T RegionSize  = (SIZE_T)((Iteration % 8) + 1) * 0x1000;

    printf("[target] calling NtAllocateVirtualMemory(RegionSize=0x%llX, PAGE_EXECUTE_READWRITE)...\n",
        (unsigned long long)RegionSize);

    NTSTATUS Status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &BaseAddress,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE   // RWX: looks like a shellcode loader, so the hook logs it
    );

    if (!NT_SUCCESS(Status)) {
        printf("[target] NtAllocateVirtualMemory failed: 0x%08lX\n", (unsigned long)Status);
        return;
    }

    printf("[target] ok: BaseAddress=%p RegionSize=0x%llX\n",
        BaseAddress, (unsigned long long)RegionSize);

    PVOID  FreeBase = BaseAddress;
    SIZE_T FreeSize = 0;
    NtFreeVirtualMemory(GetCurrentProcess(), &FreeBase, &FreeSize, MEM_RELEASE);
}

static void CallWinHttpConnect(ULONG Iteration) {
    if (!LoadWinHttp()) {
        return;
    }

    // WinHttpConnect only builds a connection handle. No DNS and no traffic happens
    // until WinHttpSendRequest, so these names are safe to use offline. They are
    // reserved TLDs (RFC 2606) and cycle so each hooked call is distinguishable.
    static PCWSTR Servers[] = { L"example.com", L"updates.example.net", L"beacon.example.invalid" };

    PCWSTR Server = Servers[Iteration % (sizeof(Servers) / sizeof(Servers[0]))];

    HINTERNET Session = pWinHttpOpen(
        L"SyscallMonitoringTool/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,   // no proxy autodetect, so nothing touches the network
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (Session == nullptr) {
        printf("[target] WinHttpOpen failed: %lu\n", GetLastError());
        return;
    }

    printf("[target] calling WinHttpConnect(%ws, %u)...\n", Server, INTERNET_DEFAULT_HTTPS_PORT);

    HINTERNET Connection = pWinHttpConnect(Session, Server, INTERNET_DEFAULT_HTTPS_PORT, 0);

    if (Connection == nullptr) {
        printf("[target] WinHttpConnect failed: %lu\n", GetLastError());
    }
    else {
        printf("[target] ok: Connection=%p\n", (void*)Connection);
        pWinHttpCloseHandle(Connection);
    }

    pWinHttpCloseHandle(Session);
}

// Point this at a real DC if you have one. localhost is the default because nothing
// listens on 389 there, so the TCP connect is refused immediately instead of timing
// out - the bind still happens, which is all the hook needs to fire.
static WCHAR LdapHost[] = L"localhost";

static void CallLdapBindSW(ULONG Iteration) {
    if (!LoadWldap32()) {
        return;
    }

    // dn and cred are PWSTR/PWCHAR (non-const), so these must be mutable arrays, not
    // string literals. Throwaway values - a cleartext LDAP_AUTH_SIMPLE bind is exactly
    // the pattern the hook is meant to catch, and the third entry is an anonymous bind.
    static WCHAR Dn0[]   = L"CN=test-user,DC=example,DC=com";
    static WCHAR Dn1[]   = L"CN=svc-backup,DC=example,DC=com";
    static WCHAR Cred0[] = L"not-a-real-password";

    static PWSTR  Dns[]   = { Dn0,   Dn1,   nullptr };
    static PWCHAR Creds[] = { Cred0, Cred0, nullptr };

    SIZE_T Slot = Iteration % (sizeof(Dns) / sizeof(Dns[0]));
    PWSTR  Dn   = Dns[Slot];
    PWCHAR Cred = Creds[Slot];

    LDAP* Session = pldap_initW(LdapHost, LDAP_PORT);
    if (Session == nullptr) {
        printf("[target] ldap_initW failed\n");
        return;
    }

    // Bound the connect so an unreachable host cannot hang the test. The bind below
    // runs either way - the hook fires on entry, not on success.
    LDAP_TIMEVAL Timeout = { 2, 0 };
    ULONG        Status  = pldap_connect(Session, &Timeout);

    if (Status != LDAP_SUCCESS) {
        printf("[target] ldap_connect: 0x%02lX (expected with no LDAP server)\n", Status);
    }

    printf("[target] calling ldap_bind_sW(%ws, dn=%ws, LDAP_AUTH_SIMPLE)...\n",
        LdapHost, Dn != nullptr ? Dn : L"<anonymous>");

    Status = pldap_bind_sW(Session, Dn, Cred, LDAP_AUTH_SIMPLE);

    if (Status != LDAP_SUCCESS) {
        printf("[target] ldap_bind_sW returned 0x%02lX%s\n", Status,
            Status == LDAP_SERVER_DOWN ? " (LDAP_SERVER_DOWN)" : "");
    }
    else {
        printf("[target] ok: bind succeeded\n");
    }

    pldap_unbind(Session);
}

// Customer-defined, continuable. Nothing else in the process uses it, so the
// handler below can dismiss it without swallowing somebody else's exception.
#define TEST_VEH_EXCEPTION_CODE 0xE0000042

// xor eax, eax ; ret  - a valid VEH that returns EXCEPTION_CONTINUE_SEARCH (0).
// It gets copied into private RWX memory, so the monitor should classify it as
// PRIVATE and unbacked - the shellcode pattern - right next to the image-backed
// handler below, which should classify as target_test.exe+RVA.
static const UCHAR PrivateVehCode[] = { 0x33, 0xC0, 0xC3 };

static PVOID PrivateVehStub = nullptr;

static LONG CALLBACK ImageVehHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == TEST_VEH_EXCEPTION_CODE) {
        // Dismissing the exception is the whole point: a vectored EXCEPTION handler
        // returning EXCEPTION_CONTINUE_EXECUTION is what makes ntdll go on to run
        // the vectored CONTINUE handlers, and that is the list the monitoring DLL
        // registered MonitorHandler on.
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL EnsurePrivateVehStub(void) {
    if (PrivateVehStub != nullptr) {
        return TRUE;
    }

    // Also trips the NtAllocateVirtualMemory hook on the way past, so this option
    // produces a SYSCALL_EVENT the first time as well.
    PrivateVehStub = VirtualAlloc(nullptr, sizeof(PrivateVehCode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (PrivateVehStub == nullptr) {
        printf("[target] VirtualAlloc for the private VEH stub failed: %lu\n", GetLastError());
        return FALSE;
    }

    memcpy(PrivateVehStub, PrivateVehCode, sizeof(PrivateVehCode));
    printf("[target] private VEH stub at %p (RWX, not image backed)\n", PrivateVehStub);
    return TRUE;
}

static void TriggerVehEvent(void) {
    if (!EnsurePrivateVehStub()) {
        return;
    }

    // First=TRUE puts the private stub at the head of the chain, which is where
    // malware wants to be - it should show up as ChainIndex 0.
    PVOID PrivateCookie = AddVectoredExceptionHandler(TRUE,
        (PVECTORED_EXCEPTION_HANDLER)PrivateVehStub);
    PVOID ImageCookie = AddVectoredExceptionHandler(FALSE, ImageVehHandler);

    if (PrivateCookie == nullptr || ImageCookie == nullptr) {
        printf("[target] AddVectoredExceptionHandler failed: %lu\n", GetLastError());
    }
    else {
        printf("[target] registered private=%p image=%p\n",
            PrivateVehStub, (void*)ImageVehHandler);
        printf("[target] raising 0x%08X to run the continue handlers...\n",
            TEST_VEH_EXCEPTION_CODE);

        RaiseException(TEST_VEH_EXCEPTION_CODE, 0, 0, nullptr);

        printf("[target] exception dismissed, execution continued\n");
    }

    // Unregister so repeated runs do not pile handlers onto the chain.
    if (ImageCookie != nullptr) {
        RemoveVectoredExceptionHandler(ImageCookie);
    }

    if (PrivateCookie != nullptr) {
        RemoveVectoredExceptionHandler(PrivateCookie);
    }
}

//
// Minimal loader-list view. Named apart from both the SDK and the monitoring
// DLL's peb.h so nothing collides - winternl.h's LDR_DATA_TABLE_ENTRY is no use
// here because it has no BaseDllName. Only the fields below are needed.
//

typedef struct _TARGET_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} TARGET_UNICODE_STRING;

typedef struct _TARGET_LDR_ENTRY {
    LIST_ENTRY            InLoadOrderLinks;
    LIST_ENTRY            InMemoryOrderLinks;
    LIST_ENTRY            InInitializationOrderLinks;
    PVOID                 DllBase;
    PVOID                 EntryPoint;
    ULONG                 SizeOfImage;
    TARGET_UNICODE_STRING FullDllName;
    TARGET_UNICODE_STRING BaseDllName;
} TARGET_LDR_ENTRY, * PTARGET_LDR_ENTRY;

typedef struct _TARGET_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} TARGET_PEB_LDR_DATA, * PTARGET_PEB_LDR_DATA;

typedef struct _TARGET_PEB {
    BOOLEAN              InheritedAddressSpace;
    BOOLEAN              ReadImageFileExecOptions;
    BOOLEAN              BeingDebugged;
    BOOLEAN              BitField;
    PVOID                Mutant;
    PVOID                ImageBaseAddress;
    PTARGET_PEB_LDR_DATA Ldr;
} TARGET_PEB, * PTARGET_PEB;

// Walk the loader list and read the first bytes of every module's code section.
// This is the hook-check / unhooking pattern: find modules through the PEB rather
// than GetModuleHandle, then compare their .text against a clean copy. The EDR
// plants decoy modules in that list whose code section is PAGE_GUARD, so the read
// raises STATUS_GUARD_PAGE_VIOLATION and PebTrapVehHandler terminates us.
static void ScanModuleCodeSections(void) {
    PTARGET_PEB Peb  = (PTARGET_PEB)__readgsqword(0x60);
    PLIST_ENTRY Head = &Peb->Ldr->InLoadOrderModuleList;

    printf("[target] walking InLoadOrderModuleList, reading each module's code...\n");

    for (PLIST_ENTRY Next = Head->Flink; Next != Head; Next = Next->Flink) {
        PTARGET_LDR_ENTRY Module = CONTAINING_RECORD(Next, TARGET_LDR_ENTRY, InLoadOrderLinks);

        if (Module->DllBase == nullptr || Module->BaseDllName.Buffer == nullptr) {
            continue;
        }

        // BaseDllName is counted, not guaranteed NUL terminated.
        WCHAR  Name[64];
        SIZE_T Count = Module->BaseDllName.Length / sizeof(WCHAR);

        if (Count > 63) {
            Count = 63;
        }

        memcpy(Name, Module->BaseDllName.Buffer, Count * sizeof(WCHAR));
        Name[Count] = L'\0';

        PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Module->DllBase;
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }

        PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((PUCHAR)Module->DllBase + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        // Headers are plain readable even on a decoy - only the code section is
        // guarded, so nothing trips until the line below.
        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(Nt);
        PUCHAR                Code    = (PUCHAR)Module->DllBase + Section->VirtualAddress;

        printf("[target]   %-24ws code at %p ... ", Name, Code);

        volatile UCHAR FirstByte = *Code;

        printf("first byte 0x%02X\n", FirstByte);
    }

    printf("[target] scan finished - no decoy was touched, process still alive\n");
}

//
// mov r10, rcx ; mov eax, <ssn> ; syscall ; ret
// The classic direct-syscall stub. Copied into private RWX memory, so the address
// the kernel returns to belongs to no image on disk.
//

static const UCHAR SyscallStubCode[] = {
    0x4C, 0x8B, 0xD1,                   /* mov r10, rcx  */
    0xB8, 0x00, 0x00, 0x00, 0x00,       /* mov eax, ssn  */
    0x0F, 0x05,                         /* syscall       */
    0xC3                                /* ret           */
};

#define SYSCALL_STUB_SSN_OFFSET 4

typedef NTSTATUS(NTAPI* PFN_NtDelayExecution)(
    BOOLEAN        Alertable,
    PLARGE_INTEGER DelayInterval
    );

static BOOL ReadSyscallNumber(const char* Name, ULONG* Ssn) {
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    PUCHAR  Stub  = (PUCHAR)GetProcAddress(Ntdll, Name);

    if (Stub == nullptr) {
        printf("[target] GetProcAddress(%s) failed: %lu\n", Name, GetLastError());
        return FALSE;
    }

    // A clean x64 stub opens with 4C 8B D1 B8 <ssn>. If it does not, someone has
    // already patched it and the dword at +4 is not a service number.
    if (Stub[0] != 0x4C || Stub[1] != 0x8B || Stub[2] != 0xD1 || Stub[3] != 0xB8) {
        printf("[target] %s is not a clean syscall stub - hooked?\n", Name);
        PrintFirstBytes(Name, Stub);
        return FALSE;
    }

    *Ssn = *(ULONG*)(Stub + 4);
    printf("[target] %s ssn = 0x%lX\n", Name, *Ssn);
    return TRUE;
}

static void TriggerUnbackedSyscall(void) {
    ULONG Ssn = 0;

    // NtDelayExecution on purpose: harmless, and it is not one of the syscalls the
    // monitoring DLL patches, so its prologue is still a readable stub.
    if (!ReadSyscallNumber("NtDelayExecution", &Ssn)) {
        return;
    }

    PUCHAR Stub = (PUCHAR)VirtualAlloc(nullptr, sizeof(SyscallStubCode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (Stub == nullptr) {
        printf("[target] VirtualAlloc failed: %lu\n", GetLastError());
        return;
    }

    memcpy(Stub, SyscallStubCode, sizeof(SyscallStubCode));
    *(ULONG*)(Stub + SYSCALL_STUB_SSN_OFFSET) = Ssn;

    printf("[target] direct syscall stub at %p (private RWX, no backing image)\n", Stub);
    printf("[target] issuing the syscall from it - the kernel returns into private\n");
    printf("[target] memory, which is what the instrumentation callback inspects...\n");

    LARGE_INTEGER Delay;
    Delay.QuadPart = -10000;   // 1 ms, relative

    PFN_NtDelayExecution Direct = (PFN_NtDelayExecution)Stub;
    NTSTATUS             Status = Direct(FALSE, &Delay);

    printf("[target] survived: syscall returned 0x%08lX - callback did not fire\n",
        (unsigned long)Status);

    VirtualFree(Stub, 0, MEM_RELEASE);
}

static void PrintMenu(void) {
    printf("\n");
    printf("[target] ----------------------------------------\n");
    printf("[target]  1) NtAllocateVirtualMemory  (RWX commit + release)\n");
    printf("[target]  2) WinHttpConnect           (loads winhttp.dll on first use)\n");
    printf("[target]  3) ldap_bind_sW             (loads wldap32.dll on first use)\n");
    printf("[target]  4) Load winhttp.dll only    (fire the loader notification, call nothing)\n");
    printf("[target]  5) Load wldap32.dll only    (fire the loader notification, call nothing)\n");
    printf("[target]  6) Dump current function bytes\n");
    printf("[target]  7) Trigger VEH chain walk    (VEH_EVENT, id 3)\n");
    printf("[target]  8) Scan module code via PEB  (KILLS: decoy guard page)\n");
    printf("[target]  9) Direct syscall from RWX   (KILLS: unbacked target)\n");
    printf("[target]  0) Exit\n");
    printf("[target] ----------------------------------------\n");
    printf("[target] choice: ");
}

// Returns the chosen number, -1 if stdin is gone, -2 if the line was not a number.
static int ReadChoice(void) {
    char Line[32];

    if (fgets(Line, sizeof(Line), stdin) == nullptr) {
        return -1;
    }

    if (strchr(Line, '\n') == nullptr) {
        int Ch;
        while ((Ch = getchar()) != '\n' && Ch != EOF) {
        }
    }

    char* End   = nullptr;
    long  Value = strtol(Line, &End, 10);

    if (End == Line) {
        return -2;
    }

    return (int)Value;
}

int main(void) {
    // Unbuffered, so nothing is lost if the process dies inside a hook.
    setvbuf(stdout, nullptr, _IONBF, 0);

    if (!ResolveNtdll()) {
        return EXIT_FAILURE;
    }

    for (ULONG Iteration = 1;; Iteration++) {
        PrintMenu();

        int Choice = ReadChoice();

        if (Choice == -1) {
            printf("[target] stdin closed, exiting\n");
            break;
        }

        switch (Choice) {
        case 1:
            CallNtAllocateVirtualMemory(Iteration);
            break;

        case 2:
            CallWinHttpConnect(Iteration);
            break;

        case 3:
            CallLdapBindSW(Iteration);
            break;

        case 4:
            LoadWinHttp();
            break;

        case 5:
            LoadWldap32();
            break;

        case 6:
            PrintFirstBytes("NtAllocateVirtualMemory", (void*)NtAllocateVirtualMemory);
            PrintFirstBytes("WinHttpConnect", (void*)pWinHttpConnect);
            PrintFirstBytes("ldap_bind_sW", (void*)pldap_bind_sW);
            break;

        case 7:
            TriggerVehEvent();
            break;

        case 8:
            ScanModuleCodeSections();
            break;

        case 9:
            TriggerUnbackedSyscall();
            break;

        case 0:
            printf("[target] exiting\n");
            return EXIT_SUCCESS;

        default:
            printf("[target] unknown choice, pick one of the numbers above\n");
            continue;   // straight back to the menu, no 5 second wait
        }

        printf("[target] waiting 5 seconds before showing the menu again...\n");
        Sleep(5000);
    }

    return EXIT_SUCCESS;
}
