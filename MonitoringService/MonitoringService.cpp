#include "MonitoringService.h"

CONST WCHAR* ServiceName = L"MonitoringService";
SERVICE_STATUS_HANDLE StatusHandle;

void ServiceControlHandler(DWORD dwControl) {

}

void ServiceMain(DWORD dwNumServicesArgs, LPSTR* lpServiceArgVectors) {
    StatusHandle = RegisterServiceCtrlHandler(ServiceName, ServiceControlHandler);

    if (!StatusHandle)
    {
        return;
    }

    SERVICE_STATUS ServiceStatus;
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;

    SetServiceStatus(StatusHandle, &ServiceStatus);
}

void wmain(int argc, WCHAR* argv[])
{
    SERVICE_TABLE_ENTRY DispatchTable[] =
    {
        { (PWCHAR)ServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { 0, 0 }
    };

    StartServiceCtrlDispatcher(DispatchTable);
}