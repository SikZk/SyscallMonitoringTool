#include "DllCommunication.h"
#include "EventLog.h"

HANDLE              IocpHandle = 0;
SECURITY_ATTRIBUTES PipeAttributes;

VOID CleanupClient(PPIPE_CLIENT Client) {
    CancelIoEx(Client->PipeHandle, 0);
    DisconnectNamedPipe(Client->PipeHandle);
    CloseHandle(Client->PipeHandle);
    std::free(Client);
}

void WINAPI IocpThread() {
    ULONG       BytesRead;
    ULONG_PTR   Key;
    OVERLAPPED* Overlapped;

    while (TRUE) {
        BOOLEAN Result = GetQueuedCompletionStatus(IocpHandle, &BytesRead, &Key, &Overlapped, INFINITE);

        if (Result == FALSE) {
            if (Overlapped == 0) {
                break;
            }
            if (Key != 0) {
                CleanupClient((PPIPE_CLIENT)Key);
            }
            continue;
        }

        if (Key == 0) {
            continue;
        }

        PPIPE_CLIENT Client = (PPIPE_CLIENT)Key;

        LogSyscall(&Client->Log);

        Result = ReadFile(Client->PipeHandle, &Client->Log, sizeof(SYSCALL_LOG), &BytesRead, Overlapped);

        if (Result == FALSE && GetLastError() != ERROR_IO_PENDING) {
            CleanupClient(Client);
        }
    }

}

void WINAPI HandleDllCommunications(_In_ HANDLE InitialPipe) {
    ULONG        LastError;
    ULONG        WaitReason;
    ULONG        BytesRead;
    HANDLE       CommunicationPipe = InitialPipe;
    PPIPE_CLIENT Client = NULL;
    BOOLEAN      ShouldStop = FALSE;
    OVERLAPPED   Overlapped = { 0 };

    Overlapped.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (Overlapped.hEvent == NULL) {
        DisconnectNamedPipe(CommunicationPipe);
        CloseHandle(CommunicationPipe);
        return;
    }

    HANDLE Events[] = { Overlapped.hEvent, StopEvent };

    while (TRUE) {
		BOOLEAN NeedCleanup = TRUE;

        do {
            ConnectNamedPipe(CommunicationPipe, &Overlapped);
            LastError = GetLastError();
            if (LastError == ERROR_IO_PENDING) {
                WaitReason = WaitForMultipleObjects(2, Events, FALSE, INFINITE);

                if (WaitReason != WAIT_OBJECT_0) {
                    ShouldStop = TRUE;
                    break;
                }
            }
            else if (LastError != ERROR_PIPE_CONNECTED) {
                break;
            }
            Client = (PPIPE_CLIENT)std::malloc(sizeof(PIPE_CLIENT));
            if (Client == 0) {
                break;
            }
            Client->PipeHandle = CommunicationPipe;

            if (CreateIoCompletionPort(CommunicationPipe, IocpHandle, (ULONG_PTR)Client, 0) != IocpHandle) {
                break;
            }

            OVERLAPPED ReadOverlapped = { 0 };
            BOOLEAN Result;

            Result = ReadFile(CommunicationPipe, &Client->Log, sizeof(SYSCALL_LOG), &BytesRead, &ReadOverlapped);
            if (Result == FALSE && GetLastError() != ERROR_IO_PENDING) {
                break;
            }

            NeedCleanup = FALSE;
        } while (FALSE);

        if (NeedCleanup == TRUE) {
            if (Client != 0) {
                std::free(Client);
                Client = 0;
            }

            DisconnectNamedPipe(CommunicationPipe);
            CloseHandle(CommunicationPipe);
        }
        if (ShouldStop == TRUE) {
            break;
        }

        CommunicationPipe = CreateNamedPipeW(
            L"\\\\.\\pipe\\MonitoringService",
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            256,
            256,
            0,
            &PipeAttributes
        );

        if (CommunicationPipe == INVALID_HANDLE_VALUE) {
            break;
        }
    }

    CloseHandle(Overlapped.hEvent);
}

void DestroyDllCommunications() {
    if (IocpHandle != 0) {
        CloseHandle(IocpHandle);
    }

    if (PipeAttributes.lpSecurityDescriptor) {
        LocalFree(PipeAttributes.lpSecurityDescriptor);
    }
}

BOOLEAN InitializeDllComms() {
    PSECURITY_DESCRIPTOR PipeDescriptor = 0;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;;FRFW;;;WD)(A;;GA;;;CO)",
        SDDL_REVISION_1,
        &PipeDescriptor,
        0)) {
        return FALSE;
    }

    PipeAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    PipeAttributes.lpSecurityDescriptor = PipeDescriptor;
    PipeAttributes.bInheritHandle = FALSE;

    HANDLE InitialPipe = CreateNamedPipeW(
        L"\\\\.\\pipe\\MonitoringService",
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        256,
        256,
        0,
        &PipeAttributes
    );

    if (InitialPipe == INVALID_HANDLE_VALUE) {
        LocalFree(PipeDescriptor);
        return FALSE;
    }
    BOOLEAN Result = FALSE;

    do {
        IocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);

        if (IocpHandle == 0)
        {
            break;
        }

        HANDLE IocpWorker = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)IocpThread, 0, 0, 0);

        if (IocpWorker == 0) {
            break;
        }

        CloseHandle(IocpWorker);

        HANDLE CommsThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HandleDllCommunications, InitialPipe, 0, 0);

        if (CommsThread == 0) {
            break;
        }

        CloseHandle(CommsThread);
        Result = TRUE;

    } while (FALSE);

    if (Result == FALSE) {
        DisconnectNamedPipe(InitialPipe);
        CloseHandle(InitialPipe);
    }
	return Result;
}