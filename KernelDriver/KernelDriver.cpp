#include "KernelDriver.h"
#include "ImageHandler.h"
#include "Apc.h"

//CONST UNICODE_STRING DllPath = RTL_CONSTANT_STRING(L"C:\\Windows\\System32\\MonitoringDll.dll");
CONST UNICODE_STRING DllPath = RTL_CONSTANT_STRING(L"C:\\Users\\user\\Desktop\\HostStuff\\x64\\Debug\\MonitoringDll.dll");
KERNEL_DRIVER_DATA* KernelDriverData = nullptr;
KERNEL_DRIVER_HEALTH_CONTEXT* KernelDriverHealthContext = nullptr;

extern "C" NTSTATUS DriverEntry(
	IN DRIVER_OBJECT* DriverObject,
	IN UNICODE_STRING* RegistryPath
) {
	KdPrint(("[SyscallMonitoringTool] DriverEntry called\n"));
	DriverObject->DriverUnload = DriverUnload;
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS initStatus = InitializeKernelDriverStructures();
	if (!NT_SUCCESS(initStatus)) {
		return initStatus;
	}

	KdPrint(("[SyscallMonitoringTool] MonitoringDllPath: %wZ", &KernelDriverData->MonitoringDllPath));

	KernelDriverHealthContext->LoadImageNotifyRoutineStatus = PsSetLoadImageNotifyRoutineEx(
		LoadImageNotifyRoutine,
		PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE
	);
	
	NTSTATUS status = GetDriverLoadHealthStatus(KernelDriverHealthContext);

	return status;
}

NTSTATUS InitializeKernelDriverStructures()
{
	NTSTATUS Status;
	PWCHAR   MonitoringDllPathBuffer = nullptr;
	CONST USHORT MaxLen = DllPath.Length + sizeof(WCHAR);

	KernelDriverHealthContext = (KERNEL_DRIVER_HEALTH_CONTEXT*)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(KERNEL_DRIVER_HEALTH_CONTEXT),
		MY_POOL_TAG
	);

	if (KernelDriverHealthContext == nullptr) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}

	KernelDriverData = (KERNEL_DRIVER_DATA*)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(KERNEL_DRIVER_DATA),
		MY_POOL_TAG
	);

	if (KernelDriverData == nullptr) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}

	MonitoringDllPathBuffer = (PWCHAR)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		MaxLen,
		MY_POOL_TAG
	);

	if (MonitoringDllPathBuffer == nullptr) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}
	MonitoringDllPathBuffer[DllPath.Length / sizeof(WCHAR)] = L'\0';

	RtlCopyMemory(MonitoringDllPathBuffer, DllPath.Buffer, DllPath.Length);

	KernelDriverData->MonitoringDllPath.Buffer = MonitoringDllPathBuffer;
	KernelDriverData->MonitoringDllPath.Length = DllPath.Length;
	KernelDriverData->MonitoringDllPath.MaximumLength = MaxLen;

	return STATUS_SUCCESS;

Cleanup:
	FreeKernelDriverStructures();
	return Status;
}

void FreeKernelDriverStructures()
{
	if (KernelDriverData != nullptr) {
		if (KernelDriverData->MonitoringDllPath.Buffer != nullptr)
			ExFreePool2(KernelDriverData->MonitoringDllPath.Buffer, MY_POOL_TAG, nullptr, 0);
		ExFreePool2(KernelDriverData, MY_POOL_TAG, nullptr, 0);
		KernelDriverData = nullptr;
	}
	if (KernelDriverHealthContext != nullptr) {
		ExFreePool2(KernelDriverHealthContext, MY_POOL_TAG, nullptr, 0);
		KernelDriverHealthContext = nullptr;
	}
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	if ((NT_SUCCESS(KernelDriverHealthContext->LoadImageNotifyRoutineStatus))) {
		PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	}

	ExFreePool(KernelDriverHealthContext);
	ExFreePool(KernelDriverData->MonitoringDllPath.Buffer);
	ExFreePool(KernelDriverData);
	KdPrint(("[SyscallMonitoringTool]: Driver unloaded\n"));
}

NTSTATUS GetDriverLoadHealthStatus(KERNEL_DRIVER_HEALTH_CONTEXT* HealthContext) {
	NTSTATUS status = STATUS_SUCCESS;
	if (NT_SUCCESS(HealthContext->LoadImageNotifyRoutineStatus) == FALSE) {
		status = STATUS_FAILED_DRIVER_ENTRY;
	}

	return status;
}

void LoadImageNotifyRoutine(
	UNICODE_STRING* FullImageName,
	HANDLE ProcessId,
	IMAGE_INFO* ImageInfo
) {	
	UNREFERENCED_PARAMETER(ProcessId);

	if (IsImageNtdll(FullImageName, ImageInfo)) {
		if (KernelDriverData->LdrLoadDllAddress != nullptr) {
			return;
		}

		void* ldrLoadDllAddress = GetLdrLoadDllAddressFromNtdll(ImageInfo->ImageBase, ImageInfo);
		if (ldrLoadDllAddress == nullptr) {
			KdPrint(("[SyscallMonitoringTool] Failed to get LdrLoadDll address from Ntdll: %wZ\n", FullImageName));
			return;
		}

		KernelDriverData->LdrLoadDllAddress = ldrLoadDllAddress;
		KdPrint(("[SyscallMonitoringTool] LdrLoadDll address: %p\n", ldrLoadDllAddress));
	}

	if (IsImageKernel32(FullImageName, ImageInfo)) {
		if (!CanInjectIntoTheProcess(PsGetCurrentProcess())) {
			return;
		}
		if (KernelDriverData->LdrLoadDllAddress == nullptr) {
			return;
		}
		KdPrint(("[SyscallMonitoringTool] Injecting into process, with id: %d", PsGetCurrentProcessId()));
		NTSTATUS status = InjectMonitoringDllViaApc(KernelDriverData->LdrLoadDllAddress);
		if (!NT_SUCCESS(status)) {
			KdPrint(("[SyscallMonitoringTool] Dll injection with kernel APC failed"));
		}
	}


	return;
}
