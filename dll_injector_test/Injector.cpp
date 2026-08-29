#include "Injector.h"

BOOL getPidFromUser(LPDWORD lpPID) {
    if (lpPID == NULL) {
        return FALSE;
    }
    info("Enter PID: ");
    if (scanf_s("%lu", lpPID) != 1 || *lpPID == 0) {
        return FALSE;
    }

    return TRUE;
}

BOOL loadDllIntoProcess(DWORD PID, wchar_t dllPath[], size_t dllPathSize) {
    DWORD TID;
    LPVOID rBuffer = NULL;
    HMODULE hKernel32 = NULL;
    HANDLE hProcess, hThread = NULL;

    hProcess = ::OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        PID
    );
    if (hProcess == NULL) {
        warn("failed to get a handle to the process, error: (%ld)", ::GetLastError());
        return FALSE;
    }

    rBuffer = ::VirtualAllocEx(
        hProcess,
        NULL,
        dllPathSize,
        (MEM_COMMIT | MEM_RESERVE),
        PAGE_READWRITE
    );
    okay("Allocated buffer to process memory w/ PAGE_READWRITE permissions'\n");
    if (rBuffer == NULL) {
        warn("Couldn't create rBuffer, error: %ld", ::GetLastError());
        return FALSE;
    }

    ::WriteProcessMemory(
        hProcess,
        rBuffer,
        dllPath,
        dllPathSize,
        NULL
    );
    okay("Wrote [%S] to process memory\n", dllPath);

    hKernel32 = ::GetModuleHandleW(L"Kernel32.dll");

    if (hKernel32 == NULL) {
        warn("failed to get a handle to Kernel32.dll, error: %ld", ::GetLastError());
        ::CloseHandle(hProcess);
        return FALSE;
    }
    okay("Got a handle to Kernel32.dll\n\\---0x%p\n", hKernel32);

    LPTHREAD_START_ROUTINE startThis = (LPTHREAD_START_ROUTINE)::GetProcAddress(hKernel32, "LoadLibraryW");
    okay("got the address of LoadLibraryW()\n\\---0x%p\n", startThis);

    hThread = ::CreateRemoteThread(hProcess, NULL, 0, startThis, rBuffer, 0, &TID);

    if (hThread == NULL) {
        warn("failed to get a handle to thread, error: %ld", ::GetLastError());
        ::CloseHandle(hProcess);
        return FALSE;
    }

    okay("got a handle to the newly-created thread (%ld)\n\\---0x%p\n", TID, hThread);
    info("waiting for the thread to finish execution\n");

    ::WaitForSingleObject(hThread, INFINITE);

    okay("thread finished successfully, cleaning up...\n");

    ::CloseHandle(hThread);
    ::CloseHandle(hProcess);

    okay("finished injecting DLL!");
    return TRUE;
}

int main() {

    DWORD PID;

    if (!getPidFromUser(&PID)) {
        warn("Invalid PID.\n");
        return EXIT_FAILURE;
    }
    info("trying to get a handle to the process (%ld)\n", PID);

    wchar_t dllPath[MAX_PATH] = L"C:\\Users\\Mikolaj\\Documents\\Programming\\SyscallMonitoringTool\\x64\\Debug\\MonitoringDll.dll";
    size_t dllPathSize = sizeof(dllPath);
    if (!loadDllIntoProcess(PID, dllPath, dllPathSize)) {
        warn("Failed to load DLL into process.\n");
        return EXIT_FAILURE;
    }


    Sleep(20000);

    return EXIT_SUCCESS;
}