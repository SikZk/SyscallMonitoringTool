#pragma once
#include <Windows.h>
#include <string>
#include <format>
#include "DllCommunication.h"

extern HANDLE EventLogHandle;

BOOLEAN InitializeEventLog();
void LogSyscall(PSYSCALL_LOG Log);
void DestroyEventLog();