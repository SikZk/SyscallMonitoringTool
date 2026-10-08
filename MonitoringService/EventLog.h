#pragma once
#include <Windows.h>
#include <string>
#include <format>
#include "DllCommunication.h"
#include <vector>
#include <winevt.h>
#include "Yara.h"

extern HANDLE EventLogHandle;

typedef struct _EVENT_LOG_QUERY
{
    std::wstring id;
    std::wstring query;
} EVENT_LOG_QUERY, * PEVENT_LOG_QUERY;

typedef struct _SERVICE_CONFIG
{
    std::vector<EVENT_LOG_QUERY> EventLogs;
} SERVICE_CONFIG, * PSERVICE_CONFIG;

typedef struct _SUBSCRIPTION_CONTEXT
{
    EVT_HANDLE   Subscription;
    HANDLE       SignalEvent;
    std::wstring QueryId;
} SUBSCRIPTION_CONTEXT, * PSUBSCRIPTION_CONTEXT;

BOOLEAN InitializeEventLog();
void LogSyscall(PSYSCALL_TELEMETRY Log);
void LogHook(PHOOK_TELEMETRY Log);
void LogVeh(PVEH_TELEMETRY Log);
void DestroyEventLog();
BOOLEAN InitializeSubscriptions();
ULONG GetPidFromEventData(EVT_HANDLE Event);
VOID LogScan(_In_ PSCAN_LOG ScanLog);