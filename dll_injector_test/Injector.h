#pragma once

#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#define okay(msg, ... ) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ... ) printf("[i] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ... ) printf("[!] " msg "\n", ##__VA_ARGS__)

BOOL getPidFromUser(LPDWORD lpPID);
BOOL loadDllIntoProcess(DWORD PID);