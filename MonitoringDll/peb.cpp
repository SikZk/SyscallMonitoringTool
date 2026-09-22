#include "peb.h"

PVOID  FakeNtdll;
SIZE_T FakeNtdllSize;

PVOID  FakeKernel32;
SIZE_T FakeKernel32Size;

LPCWSTR FakeNtdllName = L"ntd2ll.dll";
LPCWSTR FakeNtdllPath = L"C:\\Windows\\System32\\ntd2l.dll";

LPCWSTR FakeKernel32Name = L"kern3l32.dll";
LPCWSTR FakeKernel32Path = L"C:\\Windows\\System32\\kern3l32.dll";


PLDR_DATA_TABLE_ENTRY FindLdrEntry(
    _In_ LPCWSTR ModuleName
) {
    PLIST_ENTRY Head = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;

    for (PLIST_ENTRY Next = Head->Flink; Next != Head; Next = Next->Flink)
    {
        PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (_wcsicmp(Entry->BaseDllName.Buffer, ModuleName) == 0)
        {
            return Entry;
        }
    }

    return 0;
}
FORCEINLINE VOID NTAPI_INLINE RtlInitUnicodeString(
    _Out_      PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString
) {
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}

BOOLEAN CreateDllDecoy(
    _In_  PVOID   RealDll,
    _Out_ PVOID* DllAddress,
    _Out_ PSIZE_T DllSize
) {
    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(RealDll);
    if (NtHeaders == 0) {
        return FALSE;
    }

    PUCHAR FakeDll = (PUCHAR)VirtualAlloc(0, NtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (FakeDll == 0) {
        return FALSE;
    }
    memcpy(FakeDll, RealDll, NtHeaders->OptionalHeader.SizeOfImage);

    // get .text section
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
    ULONG                 OldProtect;

    BOOLEAN Result = VirtualProtect(FakeDll + Section->VirtualAddress, Section->Misc.VirtualSize, PAGE_EXECUTE_READ | PAGE_GUARD, &OldProtect);

    if (Result == FALSE) {
        VirtualFree(FakeDll, 0, MEM_RELEASE);
        return FALSE;
    }

    *DllAddress = FakeDll;
    *DllSize = NtHeaders->OptionalHeader.SizeOfImage;
    return TRUE;
}
LONG NTAPI PebTrapVehHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo ) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    PUCHAR ExceptionAddress = (PUCHAR)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];

    if (ExceptionAddress >= (PUCHAR)FakeNtdll && ExceptionAddress < (PUCHAR)FakeNtdll + FakeNtdllSize
        ||
        ExceptionAddress >= (PUCHAR)FakeKernel32 && ExceptionAddress < (PUCHAR)FakeKernel32 + FakeKernel32Size)
    {
        TerminateProcess(GetCurrentProcess(), 0);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

FORCEINLINE VOID NTAPI_INLINE InsertHeadList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Entry
) {
    PLIST_ENTRY NextEntry = ListHead->Flink;

    Entry->Flink = NextEntry;
    Entry->Blink = ListHead;
    NextEntry->Blink = Entry;
    ListHead->Flink = Entry;
}

PLDR_DATA_TABLE_ENTRY
InsertFakeLdrEntry(
    _In_ PLDR_DATA_TABLE_ENTRY RealEntry,
    _In_ PVOID                 FakeDllBase,
    _In_ LPCWSTR               FakeBaseName,
    _In_ LPCWSTR               FakeFullName,
    _In_ PLDR_DATA_TABLE_ENTRY InsertAfter
) {
    PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)HeapAlloc(GetProcessHeap(), 0, sizeof(LDR_DATA_TABLE_ENTRY));
    if (Entry == 0) {
        return 0;
    }
    memcpy(Entry, RealEntry, sizeof(LDR_DATA_TABLE_ENTRY));
    Entry->DllBase = FakeDllBase;
    Entry->EntryPoint = 0;
    RtlInitUnicodeString(&Entry->BaseDllName, FakeBaseName);
    RtlInitUnicodeString(&Entry->FullDllName, FakeFullName);

    InsertHeadList(&InsertAfter->InLoadOrderLinks, &Entry->InLoadOrderLinks);
    InsertHeadList(&InsertAfter->InMemoryOrderLinks, &Entry->InMemoryOrderLinks);
    return Entry;
}

void InitializePebTraps() {

    PLDR_DATA_TABLE_ENTRY NtdllLdrEntry = FindLdrEntry(L"ntdll.dll");
    PLDR_DATA_TABLE_ENTRY Kernel32LdrEntry = FindLdrEntry(L"kernel32.dll");

    BOOLEAN Result = CreateDllDecoy(NtdllLdrEntry->DllBase, &FakeNtdll, &FakeNtdllSize);

    if (Result == FALSE) {
        return;
    }

    Result = CreateDllDecoy(Kernel32LdrEntry->DllBase, &FakeKernel32, &FakeKernel32Size);

    if (Result == FALSE) {
        return;
    }
    
    PVOID Handle = AddVectoredExceptionHandler(FALSE, PebTrapVehHandler);

    if (Handle == 0) {
        return;
    }

    PLDR_DATA_TABLE_ENTRY FakeNtdllEntry = InsertFakeLdrEntry(
        NtdllLdrEntry,
        FakeNtdll,
        FakeNtdllName,
        FakeNtdllPath,
        (PLDR_DATA_TABLE_ENTRY)(NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList.Flink)
    );
    
    InsertFakeLdrEntry(
        Kernel32LdrEntry,
        FakeKernel32,
        FakeKernel32Name,
        FakeKernel32Path,
        FakeNtdllEntry
    );
}