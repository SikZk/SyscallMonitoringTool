#pragma once
#include "MonitoringService.h"
#include <Windows.h>
#include <sddl.h>
#include <cstdlib>


#define MAX_SYSCALL_NAME_LENGTH 32
#define MAX_PARAMETER_COUNT     12
#define MAX_NAME_LENGTH         32
#define MAX_CALLSTACK_SIZE      12
#define NUMBER_OF_HOOKS         12

extern HANDLE              IocpHandle;
extern SECURITY_ATTRIBUTES PipeAttributes;

typedef enum _PARAMETER_TYPE
{
	ParamTypeInt,         // PVOID
	ParamTypeString,      // ANSI string
	ParamTypeWideString,  // Unicode string
	ParamTypeBinary       // Raw binary data
} PARAMETER_TYPE;

typedef struct _PARAMETER_ENTRY
{
	PARAMETER_TYPE Type;    // Type of the parameter
	ULONG          Size;    // Size of the parameter data in bytes
	ULONG          Offset;  // Offset into Data[] where this parameter's value starts
} PARAMETER_ENTRY, * PPARAMETER_ENTRY;

typedef struct _HOOK_TELEMETRY
{
	CHAR            Name[MAX_NAME_LENGTH];             // Name of the hook that was executed
	SIZE_T          Timestamp;
	ULONG           ProcessId;                         // ID of the current process
	ULONG           ThreadId;                          // ID of the current thread
	PVOID           Callstack[MAX_CALLSTACK_SIZE];     // Return addresses in the call stack
	UCHAR           NumberOfParameters;                // Number of parameters
	ULONG           DataSize;                          // Size of the Data[] buffer that we used
	PARAMETER_ENTRY Parameters[MAX_PARAMETER_COUNT];   // Parameter descriptors
	UCHAR           Data[512];                         // Buffer for all parameter values

} HOOK_TELEMETRY, * PHOOK_TELEMETRY;


typedef struct _SYSCALL_TELEMETRY {
	CHAR SyscallName[MAX_SYSCALL_NAME_LENGTH];
	SIZE_T Timestamp;
	ULONG ProcessId;
	ULONG ThreadId;
	void* Caller;
	UCHAR NumberOfParameters;
	void* Parameters[MAX_PARAMETER_COUNT];
} SYSCALL_TELEMETRY, * PSYSCALL_TELEMETRY;

#define SYSCALL 0
#define HOOK    1

typedef struct _TELEMETRY {
    UCHAR Tag;

    union
    {
        SYSCALL_TELEMETRY Syscall;
        HOOK_TELEMETRY    Hook;
    };

} TELEMETRY, * PTELEMETRY;

typedef struct _PIPE_CLIENT
{
    HANDLE    PipeHandle;
    TELEMETRY Telemetry;
} PIPE_CLIENT, * PPIPE_CLIENT;

BOOLEAN InitializeDllComms();
void DestroyDllCommunications();
void WINAPI HandleDllCommunications(_In_ HANDLE InitialPipe);
void WINAPI IocpThread();