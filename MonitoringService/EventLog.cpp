#include "EventLog.h"

HANDLE EventLogHandle;

BOOLEAN InitializeEventLog() {
	EventLogHandle = RegisterEventSourceW(0, L"MonitoringService");

	if (EventLogHandle == 0) {
		OutputDebugStringA("[Svc] RegisterEventSource FAILED\n");
		return FALSE;
	}
	return TRUE;
}

void DestroyEventLog() {
	if (EventLogHandle != 0) {
		DeregisterEventSource(EventLogHandle);
	}
}


void LogHook(_In_ PHOOK_TELEMETRY Log) {
	PCSTR Strings[6];

	std::string Timestamp = std::to_string(Log->Timestamp);
	std::string ProcessId = std::to_string(Log->ProcessId);
	std::string ThreadId = std::to_string(Log->ThreadId);
	
	ULONG_PTR   Temp;
	std::string Callstack;

	for (ULONG Index = 0; Index < MAX_CALLSTACK_SIZE; Index++) {
		Temp = (ULONG_PTR)Log->Callstack[Index];

		if (Temp == 0)
		{
			break;
		}

		Callstack += std::vformat("0x{:016X}\n", std::make_format_args(Temp));
	}

	std::string Params;
	for (ULONG Index = 0; Index < Log->NumberOfParameters; Index++)
	{
		PPARAMETER_ENTRY Entry = &Log->Parameters[Index];
		PVOID Data = &Log->Data[Entry->Offset];
	
		switch (Entry->Type) {
		case ParamTypeInt:
			Temp = *(ULONG_PTR*)Data;
			Params += std::vformat("0x{:016X}\n", std::make_format_args(Temp));
			break;

		case ParamTypeString:
			Params += std::string((PCSTR)Data, Entry->Size) + "\n";
			break;

		case ParamTypeWideString:
		{
			INT Length = WideCharToMultiByte(CP_UTF8, 0, (PCWSTR)Data, Entry->Size / sizeof(WCHAR), 0, 0, 0, 0);
			std::string Converted(Length, '\0');
			WideCharToMultiByte(CP_UTF8, 0, (PCWSTR)Data, Entry->Size / sizeof(WCHAR), Converted.data(), Length, 0, 0);
			Params += Converted + "\n";
			break;
		}

		default:
			break;
		}

	}

	Strings[0] = Log->Name;
	Strings[1] = Timestamp.data();
	Strings[2] = ProcessId.data();
	Strings[3] = ThreadId.data();
	Strings[4] = Callstack.data();
	Strings[5] = Params.data();

	ReportEventA(EventLogHandle, 0, 1, HOOK_EVENT, 0, 6, 0, Strings, 0);
}

void LogSyscall(_In_ PSYSCALL_TELEMETRY Log) {
	PCSTR Strings[6];

	std::string Timestamp = std::to_string(Log->Timestamp);
	std::string ProcessId = std::to_string(Log->ProcessId);
	std::string ThreadId = std::to_string(Log->ThreadId);

	ULONG_PTR   Temp = (ULONG_PTR)Log->Caller;
	std::string RetAddr = std::vformat("0x{:016X}", std::make_format_args(Temp));

	std::string Params;

	for (ULONG Index = 0; Index < Log->NumberOfParameters; Index++) {
		Temp = (ULONG_PTR)Log->Parameters[Index];
		Params += std::vformat("0x{:016X}\n", std::make_format_args(Temp));
	}

	Strings[0] = Log->SyscallName;
	Strings[1] = Timestamp.data();
	Strings[2] = ProcessId.data();
	Strings[3] = ThreadId.data();
	Strings[4] = RetAddr.data();
	Strings[5] = Params.data();

	if (!ReportEventA(
			EventLogHandle,
			EVENTLOG_INFORMATION_TYPE,
			1,
			SYSCALL_EVENT,
			0,
			6,
			0,
			Strings,
			0
	)) {
		OutputDebugStringA("[Svc] ReportEvent FAILED\n");
	}
}