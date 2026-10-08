#include "Yara.h"
#include <yara.h>
#include <filesystem>
#include <TlHelp32.h>
#include <sstream>
#include <iomanip>
#include "EventLog.h"
#include <unordered_map>
#include <mutex>

namespace fs = std::filesystem;

YR_RULES* Rules = 0;

//
// A single PowerShell invocation raises several script-block (4104) and module
// (4103) events in quick succession, all naming the same process. Scanning a
// whole address space once per event is both slow and a pile of identical
// records, so a pid is rescanned only after this long.
//
#define SCAN_COOLDOWN_MS 10000

static std::unordered_map<ULONG, ULONGLONG> LastScanTick;
static std::mutex                           LastScanLock;

static BOOLEAN ShouldScan(ULONG ProcessId)
{
	ULONGLONG                   Now = GetTickCount64();
	std::lock_guard<std::mutex> Guard(LastScanLock);

	auto Entry = LastScanTick.find(ProcessId);

	if (Entry != LastScanTick.end() && Now - Entry->second < SCAN_COOLDOWN_MS)
	{
		return FALSE;
	}

	if (LastScanTick.size() > 512)
	{
		for (auto It = LastScanTick.begin(); It != LastScanTick.end(); )
		{
			It = (Now - It->second >= SCAN_COOLDOWN_MS) ? LastScanTick.erase(It)
			                                            : std::next(It);
		}
	}

	LastScanTick[ProcessId] = Now;
	return TRUE;
}

INT ScanCallback(YR_SCAN_CONTEXT* Context, INT Message, PVOID MessageData, PVOID UserData) { 
	PSCAN_LOG  ScanLog = (PSCAN_LOG)UserData;

	if (Message == CALLBACK_MSG_RULE_MATCHING) {
		YR_RULE* Rule = (YR_RULE*)MessageData;
		YR_STRING* String = 0;
		YR_MATCH* Match = 0;

		RULE_MATCH RuleHit{};
		RuleHit.RuleName = Rule->identifier;


		yr_rule_strings_foreach(Rule, String) {
			yr_string_matches_foreach(Context, String, Match)
			{
				STRING_MATCH StringHit{};

				StringHit.Identifier = String->identifier;
				StringHit.Address = (SIZE_T)Match->offset;

				RuleHit.Strings.push_back(StringHit);
			}
		}
		ScanLog->Matches.push_back(RuleHit);
	}
	return CALLBACK_CONTINUE;

}
std::string GetProcessNameByPid(DWORD ProcessId)
{
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Snapshot == INVALID_HANDLE_VALUE) {
		return "<unknown>";
	}

	PROCESSENTRY32W Entry = {};
	Entry.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(Snapshot, &Entry)) {
		do {
			if (Entry.th32ProcessID == ProcessId) {
				CHAR NameBuffer[MAX_PATH] = { 0 };

				WideCharToMultiByte(
					CP_UTF8, 0,
					Entry.szExeFile, -1,
					NameBuffer, MAX_PATH,
					0,
					0
				);

				CloseHandle(Snapshot);

				return std::string(NameBuffer);
			}

		} while (Process32NextW(Snapshot, &Entry));
	}

	CloseHandle(Snapshot);
	return "<unknown>";
}
std::string FormatForEventLog(PSCAN_LOG ScanLog) {
	std::ostringstream Stream;
	Stream << "Process: " << ScanLog->ProcessName << " (PID: " << ScanLog->ProcessId << ")\r\n";

	if (ScanLog->Success == FALSE) {
		Stream << "Scan failed: could not read process memory.\r\n";
		return Stream.str();
	}

	Stream << "Rules matched: " << ScanLog->Matches.size() << "\r\n";
	for (const auto& Rule : ScanLog->Matches) {
		Stream << "\r\nRule: " << Rule.RuleName << "\r\n";

		for (const auto& String : Rule.Strings)
		{
			Stream << "  " << String.Identifier
				<< " at 0x"
				<< std::uppercase << std::hex
				<< std::setw(16) << std::setfill('0')
				<< String.Address
				<< std::dec << "\r\n";
		}
	}
	return Stream.str();
}

VOID ScanProcess(ULONG ProcessId) {
	//
	// An event can name a process that has already exited - common for script
	// hosts, which finish long before the log entry is dispatched. Scanning those
	// just produces a "could not read process memory" record per dead pid, so
	// drop them before they reach the log.
	//
	HANDLE Probe = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);

	if (Probe == 0)
	{
		return;
	}

	CloseHandle(Probe);

	if (ShouldScan(ProcessId) == FALSE)
	{
		return;
	}

	SCAN_LOG ScanLog{};
	ScanLog.ProcessId = ProcessId;
	ScanLog.ProcessName = GetProcessNameByPid(ProcessId);
	ScanLog.Success = FALSE;

	INT Status = yr_rules_scan_proc(
		Rules,
		(UINT)(ProcessId),
		0,
		ScanCallback,
		&ScanLog,
		0
	);
	if (Status == ERROR_SUCCESS)
	{
		ScanLog.Success = TRUE;
	}

	LogScan(&ScanLog);
}

BOOL AddRuleFromFile(YR_COMPILER* Compiler, std::string_view FilePath)
{
	FILE* RuleFile;
	INT   Result = fopen_s(&RuleFile, FilePath.data(), "r");

	if (Result != ERROR_SUCCESS)
	{
		return FALSE;
	}

	Result = yr_compiler_add_file(Compiler, RuleFile, 0, FilePath.data());
	fclose(RuleFile);

	if (Result != ERROR_SUCCESS)
	{
		return FALSE;
	}

	return TRUE;
}

BOOLEAN CompileRulesFromFolder(YR_COMPILER* Compiler)
{
	BOOLEAN Result = TRUE;

	std::error_code Ec;
	fs::recursive_directory_iterator Begin("C:\\Users\\user\\Desktop\\HostStuff\\YaraRules", Ec);

	if (Ec)
	{
		return FALSE;
	}

	for (const auto& entry : Begin)
	{
		if (entry.exists() && entry.is_regular_file())
		{
			Result = AddRuleFromFile(Compiler, entry.path().string());

			if (Result == FALSE)
			{
				break;
			}
		}
	}

	return Result;
}

BOOLEAN InitializeScanner() {
	if (yr_initialize() != ERROR_SUCCESS)
	{
		return FALSE;
	}

	YR_COMPILER* Compiler = 0;

	if (yr_compiler_create(&Compiler) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	BOOLEAN Result = CompileRulesFromFolder(Compiler);

	if (Result == FALSE)
	{
		yr_compiler_destroy(Compiler);
		return FALSE;
	}

	Result = yr_compiler_get_rules(Compiler, &Rules);
	yr_compiler_destroy(Compiler);

	if (Result != ERROR_SUCCESS)
	{
		return FALSE;
	}

	return TRUE;
}

void DestroyScanner() {
	if (Rules != 0)
	{
		yr_rules_destroy(Rules);
		Rules = 0;
	}

	yr_finalize();
}
