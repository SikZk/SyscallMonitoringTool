#pragma once
#include "MonitoringService.h"
#include <Windows.h>
#include <sddl.h>
#include <cstdlib>


#define MAX_SYSCALL_NAME_LENGTH 32
#define MAX_PARAMETER_COUNT     12

extern HANDLE              IocpHandle;
extern SECURITY_ATTRIBUTES PipeAttributes;

typedef struct _SYSCALL_LOG
{
    CHAR   SyscallName[MAX_SYSCALL_NAME_LENGTH];
    SIZE_T Timestamp;
    ULONG  ProcessId;                           
    ULONG  ThreadId;                             
    PVOID  Caller;
    UCHAR  NumberOfParameters;                   
    PVOID  Parameters[MAX_PARAMETER_COUNT];     
} SYSCALL_LOG, * PSYSCALL_LOG;

typedef struct _PIPE_CLIENT {
    HANDLE      PipeHandle;
    SYSCALL_LOG Log;
} PIPE_CLIENT, * PPIPE_CLIENT;

BOOLEAN InitializeDllComms();
void DestroyDllCommunications();
void WINAPI HandleDllCommunications(_In_ HANDLE InitialPipe);
void WINAPI IocpThread();