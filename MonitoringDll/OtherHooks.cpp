#include <Windows.h>
#include "Ntapi.h"
#include <detours.h>
#include "OtherHooks.h"
#include "Hooks.h"

PFN_WinHttpConnect RealWinHttpConnect = nullptr;
PFN_LdapBindSW     RealLdapBindSW = nullptr;
extern HANDLE PipeHandle;

void AddParam(
    PHOOK_TELEMETRY Telem,
    UCHAR Index,
    PARAMETER_TYPE Type,
    PVOID Data,
    ULONG Size
) {
    ULONG Offset = Telem->DataSize;

    if (Offset + Size > 512)
    {
        Size = 512 - Offset;
    }

    Telem->Parameters[Index].Type = Type;
    Telem->Parameters[Index].Offset = Offset;
    Telem->Parameters[Index].Size = Size;

    if (Data != 0 && Size > 0)
    {
        memcpy(&Telem->Data[Offset], Data, Size);
        Telem->DataSize += Size;
    }
}


VOID NTAPI DllNotificationCallback(
    _In_     ULONG                      Reason,
    _In_     PLDR_DLL_NOTIFICATION_DATA Data,
    _In_opt_ PVOID                      Context
) {
    if (Reason != LDR_DLL_NOTIFICATION_REASON_LOADED) {
        return;
    }

    if (_wcsicmp(Data->Loaded.BaseDllName->Buffer, L"winhttp.dll") == 0)
    {
        InstallWinHttpHooks(Data->Loaded.DllBase);
    }
    else if (_wcsicmp(Data->Loaded.BaseDllName->Buffer, L"wldap32.dll") == 0)
    {
        InstallWldap32Hooks(Data->Loaded.DllBase);
    }
}

HINTERNET WINAPI WinHttpConnectHook(
    PVOID hSession,
    LPCWSTR pswzServerName,
    USHORT nServerPort,
    DWORD dwReserved
) {
    HINTERNET ConnectionHandle = RealWinHttpConnect(
        hSession,
        pswzServerName,
        nServerPort,
        dwReserved
    );
    PTELEMETRY_LOG Log = (PTELEMETRY_LOG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TELEMETRY_LOG));
    if (Log == 0) {
        return ConnectionHandle;
    }

    Log->Telemetry.Tag = HOOK;
    PHOOK_TELEMETRY Telem = &Log->Telemetry.Hook;

    memcpy(Telem->Name, "WinHttpConnect", sizeof("WinHttpConnect"));
    Telem->ProcessId = GetCurrentProcessId();
    Telem->ThreadId = GetCurrentThreadId();

    GetSystemTimePreciseAsFileTime((LPFILETIME)&Telem->Timestamp);

    RtlCaptureStackBackTrace(1, MAX_CALLSTACK_SIZE, Telem->Callstack, NULL);

    Telem->NumberOfParameters = 5;

    AddParam(Telem, 0, ParamTypeInt, &hSession, sizeof(hSession));
    AddParam(Telem, 1, ParamTypeWideString, (PVOID)pswzServerName, wcslen(pswzServerName) * sizeof(WCHAR));
    AddParam(Telem, 2, ParamTypeInt, &nServerPort, sizeof(PVOID));
    AddParam(Telem, 3, ParamTypeInt, &dwReserved, sizeof(PVOID));
    AddParam(Telem, 4, ParamTypeInt, &ConnectionHandle, sizeof(PVOID));

    WriteFile(PipeHandle, &Log->Telemetry, sizeof(TELEMETRY), NULL, &Log->Overlapped);

    return ConnectionHandle;
}

void InstallWinHttpHooks(PVOID DllBase) {
    RealWinHttpConnect = (decltype(WinHttpConnect)*)GetProcAddress((HMODULE)DllBase, "WinHttpConnect");
    if (RealWinHttpConnect == 0) {
        return;
    }

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)RealWinHttpConnect, WinHttpConnectHook);
    DetourTransactionCommit();
}

ULONG LDAPAPI LdapBindHook(
    LDAP* ld,
    PWSTR dn,
    PWCHAR cred,
    ULONG method
) {
	ULONG Result = RealLdapBindSW(
        ld,
        dn,
        cred,
        method
    );

    PTELEMETRY_LOG Log = (PTELEMETRY_LOG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TELEMETRY_LOG));
    if (Log == 0) {
        return Result;
    }

    Log->Telemetry.Tag = HOOK;
    PHOOK_TELEMETRY Telem = &Log->Telemetry.Hook;

    memcpy(Telem->Name, "ldap_bind_sW", sizeof("ldap_bind_sW"));
    Telem->ProcessId = GetCurrentProcessId();
    Telem->ThreadId = GetCurrentThreadId();

    GetSystemTimePreciseAsFileTime((LPFILETIME)&Telem->Timestamp);

    RtlCaptureStackBackTrace(1, MAX_CALLSTACK_SIZE, Telem->Callstack, NULL);

    Telem->NumberOfParameters = 5;

    AddParam(Telem, 0, ParamTypeInt, &ld, sizeof(PVOID));
    AddParam(Telem, 1, ParamTypeWideString, dn, wcslen(dn) * sizeof(WCHAR));
    AddParam(Telem, 2, ParamTypeWideString, cred, wcslen(cred) * sizeof(WCHAR));
    AddParam(Telem, 3, ParamTypeInt, &method, sizeof(PVOID));
    AddParam(Telem, 4, ParamTypeInt, &Result, sizeof(PVOID));

    WriteFile(PipeHandle, &Log->Telemetry, sizeof(TELEMETRY), NULL, &Log->Overlapped);

    return Result;
}
void InstallWldap32Hooks(PVOID DllBase) {
    RealLdapBindSW = (decltype(ldap_bind_sW)*)GetProcAddress((HMODULE)DllBase, "ldap_bind_sW");

    if (RealLdapBindSW == 0) {
        return;
    }

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)RealLdapBindSW, LdapBindHook);
    DetourTransactionCommit();
}