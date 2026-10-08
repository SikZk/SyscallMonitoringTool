#include "EventLog.h"
#include <fstream>
#include <nlohmann/json.hpp>
#include "Yara.h"
#pragma comment(lib, "wevtapi.lib")
using json = nlohmann::json;

HANDLE EventLogHandle;
extern HANDLE                     StopEvent;
std::vector<SUBSCRIPTION_CONTEXT> Subscriptions;

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

VOID LogVeh(_In_ PVEH_TELEMETRY Log)
{
	PCSTR Strings[6];

	std::string Timestamp = std::to_string(Log->Timestamp);
	std::string ProcessId = std::to_string(Log->ProcessId);
	std::string ThreadId = std::to_string(Log->ThreadId);


	ULONG_PTR   Temp = (ULONG_PTR)Log->Handler;
	std::string Handler = std::vformat("0x{:016X}", std::make_format_args(Temp));

	PCSTR MemoryKind;
	switch (Log->MemoryKind) {
		case VehMemoryImage:   MemoryKind = "IMAGE";   break;
		case VehMemoryMapped:  MemoryKind = "MAPPED";  break;
		case VehMemoryPrivate: MemoryKind = "PRIVATE"; break;
		default:               MemoryKind = "UNKNOWN"; break;
	}

	Log->ModuleName[MAX_MODULE_NAME_LENGTH - 1] = L'\0';

	std::string ModuleName;

	if (Log->ModuleName[0] == L'\0') {
		ModuleName = "<none>";
	}
	else {
		INT Length = WideCharToMultiByte(CP_UTF8, 0, Log->ModuleName, -1, 0, 0, 0, 0);

		if (Length > 0) {
			ModuleName.resize(Length - 1);
			WideCharToMultiByte(CP_UTF8, 0, Log->ModuleName, -1, ModuleName.data(), Length, 0, 0);
		}
	}

	Strings[0] = Timestamp.data();
	Strings[1] = ProcessId.data();
	Strings[2] = ThreadId.data();
	Strings[3] = Handler.data();
	Strings[4] = MemoryKind;
	Strings[5] = ModuleName.data();

	ReportEventA(EventLogHandle, 0, 1, VEH_EVENT, 0, 6, 0, Strings, 0);
}

VOID LogScan(_In_ PSCAN_LOG ScanLog) {
	std::string Log = FormatForEventLog(ScanLog);
	PCSTR       Strings = Log.c_str();

	ReportEventA(EventLogHandle, 0, 1, SCAN_EVENT, 0, 1, 0, &Strings, 0);
}

ULONG GetPidFromEventData(EVT_HANDLE Event) {
	HANDLE Context = EvtCreateRenderContext(0, 0, EvtRenderContextSystem);
	if (Context == 0) {
		return 0;
	}

	BOOLEAN      Result;
	ULONG        BufferSize = 0;
	ULONG        BufferUsed = 0;
	ULONG        PropertyCount = 0;
	PEVT_VARIANT Property = 0;

	Result = EvtRender(
		Context,
		Event,
		EvtRenderEventValues,
		BufferSize,
		Property,
		&BufferUsed,
		&PropertyCount
	);
	if (Result == FALSE && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		EvtClose(Context);
		return 0;
	}
	BufferSize = BufferUsed;
	Property = (PEVT_VARIANT)std::malloc(BufferUsed);

	if (Property == 0)
	{
		EvtClose(Context);
		return 0;
	}

	Result = EvtRender(
		Context,
		Event,
		EvtRenderEventValues,
		BufferSize,
		Property,
		&BufferUsed,
		&PropertyCount
	);

	EvtClose(Context);

	ULONG ProcessId = 0;

	if (Result == TRUE)
	{
		ProcessId = Property[EvtSystemProcessID].UInt32Val;
	}

	std::free(Property);
	return ProcessId;
}

VOID from_json(const json& j, EVENT_LOG_QUERY& e)
{
	std::string id = j.at("id").get<std::string>();
	std::string query = j.at("query").get<std::string>();

	e.id.assign(id.begin(), id.end());
	e.query.assign(query.begin(), query.end());
}

VOID from_json(const json& j, SERVICE_CONFIG& e)
{
	if (j.contains("event_log"))
	{
		e.EventLogs = j.at("event_log").get<std::vector<EVENT_LOG_QUERY>>();
	}
}

VOID DestroySubscriptions()
{
	for (auto& Subscription : Subscriptions)
	{
		EvtClose(Subscription.Subscription);
		CloseHandle(Subscription.SignalEvent);
	}

	Subscriptions.clear();
}

ULONG WINAPI SubscriptionThread() {
	std::vector<HANDLE> WaitHandles;
	WaitHandles.push_back(StopEvent);

	for (const auto& Subscription : Subscriptions)
	{
		WaitHandles.push_back(Subscription.SignalEvent);
	}


	EVT_HANDLE Events[16];
	ULONG      Returned;

	while (TRUE) {
		ULONG Wait = WaitForMultipleObjects((ULONG)WaitHandles.size(), WaitHandles.data(), FALSE, INFINITE);

		if (Wait == WAIT_FAILED)
		{
			break;
		}

		if (Wait == WAIT_OBJECT_0)
		{
			break;
		}
		ULONG                 Index = Wait - WAIT_OBJECT_0 - 1;
		SUBSCRIPTION_CONTEXT* Ctx = &Subscriptions[Index];

		while (EvtNext(Ctx->Subscription, 16, Events, 0, 0, &Returned))
		{
			for (ULONG Index = 0; Index < Returned; Index++)
			{
				ULONG ProcessId = GetPidFromEventData(Events[Index]);

				if (ProcessId != 0) {
					ScanProcess(ProcessId);
				}

				EvtClose(Events[Index]);
				Events[Index] = 0;
			}
		}
		ULONG NextError = GetLastError();

		if (NextError != ERROR_NO_MORE_ITEMS && NextError != ERROR_TIMEOUT)
		{
			// NOTE: this tears down every subscription permanently. The service
			// stays RUNNING but goes deaf, which looks exactly like "no events".
			break;
		}

		ResetEvent(Ctx->SignalEvent);
	}
	DestroySubscriptions();
	return 0;
}

BOOLEAN InitializeSubscriptions() {
	std::ifstream File("C:\\Users\\user\\Desktop\\HostStuff\\MonitoringService\\Config.json");
	if (File.is_open() == FALSE) {
		return FALSE;
	}

	SERVICE_CONFIG Config;
	try {
		json Json = json::parse(File);
		Config = Json.get<SERVICE_CONFIG>();
	}
	catch (const std::exception&) {
		return FALSE;
	}


	for (const auto& Query : Config.EventLogs) {
		HANDLE SignalEvent = CreateEventW(0, TRUE, TRUE, 0);
		if (SignalEvent == 0) {
			break;
		}

		EVT_HANDLE Subscription = EvtSubscribe(0, SignalEvent, 0, Query.query.c_str(), 0, 0, 0, EvtSubscribeStartAtOldestRecord);
		if (Subscription == 0)
		{
			CloseHandle(SignalEvent);
			break;
		}


		SUBSCRIPTION_CONTEXT Ctx;
		Ctx.Subscription = Subscription;
		Ctx.SignalEvent = SignalEvent;
		Ctx.QueryId = Query.id;

		Subscriptions.push_back(Ctx);
	}

	if (Subscriptions.size() != Config.EventLogs.size())
	{
		DestroySubscriptions();
		return FALSE;
	}

	HANDLE Thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SubscriptionThread, 0, 0, 0);

	if (Thread == 0)
	{
		DestroySubscriptions();
		return FALSE;
	}

	CloseHandle(Thread);
	return TRUE;
}