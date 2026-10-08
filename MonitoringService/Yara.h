#pragma once
#include <windows.h>
#include <string>
#include <vector>

typedef struct _STRING_MATCH
{
	std::string Identifier;
	ULONG_PTR   Address;
} STRING_MATCH, * PSTRING_MATCH;

typedef struct _RULE_MATCH
{
	std::string RuleName;
	std::vector<STRING_MATCH> Strings;
} RULE_MATCH, * PRULE_MATCH;

typedef struct _SCAN_LOG
{
	DWORD       ProcessId;
	std::string ProcessName;
	BOOLEAN     Success;
	std::vector<RULE_MATCH> Matches;
} SCAN_LOG, * PSCAN_LOG;

BOOLEAN InitializeScanner();
void DestroyScanner();
VOID ScanProcess(ULONG ProcessId);
std::string FormatForEventLog(PSCAN_LOG ScanLog);