#pragma once
#include <Windows.h>
#include <string>
#include <format>
#include "DllCommunication.h"

extern HANDLE EventLogHandle;

BOOLEAN InitializeEventLog();
void LogSyscall(PSYSCALL_TELEMETRY Log);
void LogHook(PHOOK_TELEMETRY Log);
void DestroyEventLog();