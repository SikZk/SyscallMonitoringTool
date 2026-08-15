#include "KernelDriver.h"
#include "ImageHandler.h"


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

	KernelDriverHealthContext->LoadImageNotifyRoutineStatus = PsSetLoadImageNotifyRoutineEx(
		LoadImageNotifyRoutine,
		PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE
	);
	
	NTSTATUS status = GetDriverLoadHealthStatus(KernelDriverHealthContext);

	return status;
}

NTSTATUS InitializeKernelDriverStructures() {
	KernelDriverHealthContext = (KERNEL_DRIVER_HEALTH_CONTEXT*)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(KERNEL_DRIVER_HEALTH_CONTEXT),
		MY_POOL_TAG
	);

	if (KernelDriverHealthContext == nullptr) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KernelDriverData = (KERNEL_DRIVER_DATA*)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(KERNEL_DRIVER_DATA),
		MY_POOL_TAG
	);

	if (KernelDriverData == nullptr) {
		ExFreePool(KernelDriverHealthContext);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	if ((NT_SUCCESS(KernelDriverHealthContext->LoadImageNotifyRoutineStatus))) {
		PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	}

	ExFreePool(KernelDriverHealthContext);
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
	UNREFERENCED_PARAMETER(ImageInfo);
	UNREFERENCED_PARAMETER(ProcessId);

	if (IsImageNtdll(FullImageName, ImageInfo)) {
		if (KernelDriverData->LdrLoadDllAddress != nullptr) {
			return;
		}

		KdPrint(("[SyscallMonitoringTool] Ntdll: %wZ\n", FullImageName));

		void* ldrLoadDllAddress = GetLdrLoadDllAddressFromNtdll(FullImageName, ImageInfo);
		if (ldrLoadDllAddress == nullptr) {
			KdPrint(("[SyscallMonitoringTool] Failed to get LdrLoadDll address from Ntdll: %wZ\n", FullImageName));
			return;
		}

		KernelDriverData->LdrLoadDllAddress = ldrLoadDllAddress;
		KdPrint(("[SyscallMonitoringTool] LdrLoadDll address: %p\n", ldrLoadDllAddress));
	}

	if (IsImageKernel32(FullImageName, ImageInfo)) {
		KdPrint(("[SyscallMonitoringTool] Kernel32: %wZ\n", FullImageName));
	}


	return;
}
