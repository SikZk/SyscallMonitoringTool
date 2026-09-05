#include "MonitoringService.h"
#include "EventLog.h"
#include "DllCommunication.h"

CONST WCHAR* ServiceName = L"MonitoringService";
SERVICE_STATUS_HANDLE StatusHandle = 0;
SERVICE_STATUS        ServiceStatus = { 0 };
HANDLE                StopEvent = 0;

void  PerformCleanup() {
    DestroyDllCommunications();
    DestroyEventLog();

    if (StopEvent != 0)
    {
        CloseHandle(StopEvent);
    }
}

void WINAPI ServiceControlHandler(DWORD dwControl) {
    if (dwControl == SERVICE_CONTROL_SHUTDOWN) {
        SetEvent(StopEvent);

        PerformCleanup();
    }
}

VOID WINAPI ServiceMain(DWORD dwNumServicesArgs, LPWSTR* lpServiceArgVectors) {
    StatusHandle = RegisterServiceCtrlHandler(ServiceName, ServiceControlHandler);

    if (!StatusHandle) {
        return;
    }

    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;

    SetServiceStatus(StatusHandle, &ServiceStatus);

    do
    {
        BOOLEAN Result = InitializeEventLog();

        if (Result == FALSE) {
            break;
        }
        StopEvent = CreateEventW(0, TRUE, FALSE, 0);
        if (StopEvent == 0) {
            break;
        }

        Result = InitializeDllComms();
        if (Result == FALSE) {
            break;
        }

        ServiceStatus.dwCurrentState = SERVICE_RUNNING;

    } while (FALSE);

    SetServiceStatus(StatusHandle, &ServiceStatus);
    if (ServiceStatus.dwCurrentState != SERVICE_RUNNING) {
        PerformCleanup();
    }
}

VOID wmain(int argc, WCHAR* argv[]) {
    SERVICE_TABLE_ENTRY DispatchTable[] =
    {
        { (PWCHAR)ServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { 0, 0 }
    };

    StartServiceCtrlDispatcher(DispatchTable);
}

