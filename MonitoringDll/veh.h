#pragma once
#include <Windows.h>

#define MAX_MODULE_NAME_LENGTH 64

typedef enum _VEH_MEMORY_KIND
{
    VehMemoryUnknown = 0, 
    VehMemoryImage,       
    VehMemoryMapped,
    VehMemoryPrivate
} VEH_MEMORY_KIND;

typedef struct _VEH_TELEMETRY
{
    SIZE_T Timestamp;
    ULONG  ProcessId;
    ULONG  ThreadId;
    PVOID  Handler;

    ULONG  MemoryKind;
    WCHAR  ModuleName[MAX_MODULE_NAME_LENGTH];
} VEH_TELEMETRY, * PVEH_TELEMETRY;

typedef struct _VECTXCPT_CALLOUT_ENTRY
{
    LIST_ENTRY                  ListEntry;
    PVOID                       Reserved;
    INT                         RefCount;
    PVECTORED_EXCEPTION_HANDLER Handler;
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;

void InitializeVehMonitor();
