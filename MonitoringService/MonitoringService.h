#pragma once
#include <stdio.h>
#include <Windows.h>

extern HANDLE StopEvent;

VOID WINAPI ServiceControlHandler(DWORD dwControl);
VOID WINAPI ServiceMain(DWORD dwNumServicesArgs, LPWSTR* lpServiceArgVectors);
void PerformCleanup();

#define SYSCALL_EVENT 0x00000001L
#define HOOK_EVENT 0x00000002L
#define VEH_EVENT 0x00000003L