#include "KernelDriver.h"

extern "C" NTSTATUS DriverEntry(
	IN DRIVER_OBJECT* DriverObject,
	IN UNICODE_STRING* RegistryPath
) {
	NTSTATUS status;
	KernelDriverHealthContext = (KERNEL_DRIVER_HEALTH_CONTEXT*)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(KERNEL_DRIVER_HEALTH_CONTEXT),
		MY_POOL_TAG
	);

	KdPrint(("[KernelDriver] DriverEntry called\n"));

	KernelDriverHealthContext->LoadImageNotifyRoutineStatus = PsSetLoadImageNotifyRoutineEx(
		LoadImageNotifyRoutine,
		PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE
	);
	
	return STATUS_SUCCESS;
}

void MyDriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	if ((NT_SUCCESS(KernelDriverHealthContext->LoadImageNotifyRoutineStatus))) {
		PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	}

	ExFreePool(KernelDriverHealthContext);
	KdPrint(("[Generic]: Driver unloaded\n"));
}

void LoadImageNotifyRoutine(
	UNICODE_STRING* FullImageName,
	HANDLE ProcessId,
	IMAGE_INFO* ImageInfo
) {
	UNREFERENCED_PARAMETER(ImageInfo);
	UNREFERENCED_PARAMETER(ProcessId);

	KdPrint(("[KernelDriver] LoadImageNotifyRoutine called\n"));
	KdPrint(("[KernelDriver] FullImageName: %wZ\n", FullImageName));

	return;
}
