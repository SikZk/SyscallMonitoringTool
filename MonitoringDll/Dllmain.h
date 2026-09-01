#pragma once
#include <windows.h>
#include <stdio.h>

void InitializeSyscallHooks();
void* FindNtdllPadding(IN void* NtdllAddress);
ULONG WINAPI IocpThread();