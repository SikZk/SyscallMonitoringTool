#include "EventLog.h"

HANDLE EventLogHandle;

BOOLEAN InitializeEventLog() {
	EventLogHandle = RegisterEventSourceW(0, L"MonitoringService");

	if (EventLogHandle == 0)
	{
		return FALSE;
	}
	return TRUE;
}

void DestroyEventLog() {
	if (EventLogHandle != 0) {
		DeregisterEventSource(EventLogHandle);
	}
}

void LogSyscall(_In_ PSYSCALL_LOG Log) {
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

	ReportEventA(EventLogHandle, 0, 1, SYSCALL_EVENT, 0, 6, 0, Strings, 0);
}