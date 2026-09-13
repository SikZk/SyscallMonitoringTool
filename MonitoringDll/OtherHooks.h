#pragma once
#include <winhttp.h>
#include <winldap.h>

using PFN_WinHttpConnect = decltype(&WinHttpConnect);
using PFN_LdapBindSW = decltype(&ldap_bind_sW);

extern PFN_WinHttpConnect RealWinHttpConnect;
extern PFN_LdapBindSW     RealLdapBindSW;

VOID NTAPI DllNotificationCallback(
    _In_     ULONG                      Reason,
    _In_     PLDR_DLL_NOTIFICATION_DATA Data,
    _In_opt_ PVOID                      Context
);

HINTERNET WINAPI WinHttpConnectHook(
    PVOID hSession,
    LPCWSTR pswzServerName,
    USHORT nServerPort,
    DWORD dwReserved
);
ULONG LDAPAPI LdapBindHook(
    LDAP* ld,
    PWSTR dn,
    PWCHAR cred,
    ULONG method
);

void InstallWldap32Hooks(PVOID DllBase);
void InstallWinHttpHooks(PVOID DllBase);