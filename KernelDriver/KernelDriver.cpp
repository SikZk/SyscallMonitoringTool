#include "KernelDriver.h"
#include "ImageHandler.h"


extern "C" NTSTATUS DriverEntry(
	IN DRIVER_OBJECT* DriverObject,
	IN UNICODE_STRING* RegistryPath
) {
	KdPrint(("[SyscallMonitoringTool] DriverEntry called\n"));
	DriverObject->DriverUnload = DriverUnload;
	UNREFERENCED_PARAMETER(RegistryPath);

	KernelDriverHealthContext = (KERNEL_DRIVER_HEALTH_CONTEXT*)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(KERNEL_DRIVER_HEALTH_CONTEXT),
		MY_POOL_TAG
	);

	if (KernelDriverHealthContext == nullptr) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KernelDriverHealthContext->LoadImageNotifyRoutineStatus = PsSetLoadImageNotifyRoutineEx(
		LoadImageNotifyRoutine,
		PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE
	);
	
	NTSTATUS status = GetDriverLoadHealthStatus(KernelDriverHealthContext);

	return status;
}



void DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	if ((NT_SUCCESS(KernelDriverHealthContext->LoadImageNotifyRoutineStatus))) {
		PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	}

	ExFreePool(KernelDriverHealthContext);
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
	KdPrint(("[SyscallMonitoringTool] LoadImageNotifyRoutine, process ID: %p\n", ProcessId));
	
	UNREFERENCED_PARAMETER(ImageInfo);
	UNREFERENCED_PARAMETER(ProcessId);

	if (IsImageNtdll(FullImageName, ImageInfo)) {
		KdPrint(("[SyscallMonitoringTool] Ntdll: %wZ\n", FullImageName));
	}

	if (IsImageKernel32(FullImageName, ImageInfo)) {
		KdPrint(("[SyscallMonitoringTool] Kernel32: %wZ\n", FullImageName));
	}


	return;
}
