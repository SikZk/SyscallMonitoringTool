#include "Hooks.h"
#include "veh.h"
#include "peb.h"

PLIST_ENTRY LdrpVectorHandlerList;
extern HANDLE PipeHandle;

LONG NTAPI DummyHandler( _In_ PEXCEPTION_POINTERS ExceptionInfo ) {
    return EXCEPTION_CONTINUE_SEARCH;
}

PLIST_ENTRY FindHandlerList() {
    PVOID Handle = AddVectoredExceptionHandler(TRUE, DummyHandler);

    if (Handle == 0)
    {
        return 0;
    }

    PLIST_ENTRY Result = ((PLIST_ENTRY)Handle)->Blink;

    RemoveVectoredExceptionHandler(Handle);
    return Result;
}

static void ClassifyHandler(PVOID Handler, PVEH_TELEMETRY Telemetry) {
    MEMORY_BASIC_INFORMATION Mbi;

    if (VirtualQuery(Handler, &Mbi, sizeof(Mbi)) == sizeof(Mbi)) {
        switch (Mbi.Type) {
        case MEM_IMAGE:   Telemetry->MemoryKind = VehMemoryImage;   break;
        case MEM_MAPPED:  Telemetry->MemoryKind = VehMemoryMapped;  break;
        case MEM_PRIVATE: Telemetry->MemoryKind = VehMemoryPrivate; break;
        default:          Telemetry->MemoryKind = VehMemoryUnknown; break;
        }
    }

    PLIST_ENTRY Head = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;

    for (PLIST_ENTRY Next = Head->Flink; Next != Head; Next = Next->Flink) {
        PLDR_DATA_TABLE_ENTRY Module = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if ((PUCHAR)Handler < (PUCHAR)Module->DllBase ||
            (PUCHAR)Handler >= (PUCHAR)Module->DllBase + Module->SizeOfImage) {
            continue;
        }

        SIZE_T Count = Module->BaseDllName.Length / sizeof(WCHAR);
        if (Count > MAX_MODULE_NAME_LENGTH - 1) {
            Count = MAX_MODULE_NAME_LENGTH - 1;
        }

        memcpy(Telemetry->ModuleName, Module->BaseDllName.Buffer, Count * sizeof(WCHAR));
        Telemetry->ModuleName[Count] = L'\0';
        break;
    }
}

void LogVeh(PEXCEPTION_POINTERS ExceptionInfo, PVOID Handler) {
    PTELEMETRY_LOG Log = (PTELEMETRY_LOG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TELEMETRY_LOG));
	if (Log == 0) {
		return;
	}

	Log->Telemetry.Tag = VEH;
	PVEH_TELEMETRY Telemetry = &Log->Telemetry.Veh;

    ClassifyHandler(Handler, Telemetry);

    GetSystemTimePreciseAsFileTime((LPFILETIME)&Telemetry->Timestamp);
	Telemetry->ProcessId = GetCurrentProcessId();
	Telemetry->ThreadId = GetCurrentThreadId();
	Telemetry->Handler = Handler;

    WriteFile(PipeHandle, &Log->Telemetry, sizeof(TELEMETRY), NULL, &Log->Overlapped);
}
LONG NTAPI MonitorHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo) {
    PLIST_ENTRY Head = LdrpVectorHandlerList;
    PLIST_ENTRY Current = Head->Flink;
    PVOID       BaseOfImage;

    while (Current != Head) {
        PVECTXCPT_CALLOUT_ENTRY Entry = CONTAINING_RECORD(Current, VECTXCPT_CALLOUT_ENTRY, ListEntry);
        PVOID                   Handler = DecodePointer(Entry->Handler);

        LogVeh(ExceptionInfo, Handler);
        Current = Current->Flink;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


void InitializeVehMonitor() {
	LdrpVectorHandlerList = FindHandlerList();

    if (LdrpVectorHandlerList == 0) {
        return;
    }

    AddVectoredContinueHandler(TRUE, MonitorHandler);
}