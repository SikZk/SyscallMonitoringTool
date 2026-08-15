#pragma once
#include <ntifs.h>

#define MY_POOL_TAG 'Drvk'

struct KERNEL_DRIVER_HEALTH_CONTEXT {
	NTSTATUS LoadImageNotifyRoutineStatus;
};

KERNEL_DRIVER_HEALTH_CONTEXT* KernelDriverHealthContext;

void LoadImageNotifyRoutine(
	UNICODE_STRING* FullImageName,
	HANDLE ProcessId,
	IMAGE_INFO* ImageInfo
);

void DriverUnload(
	PDRIVER_OBJECT DriverObject
);

NTSTATUS GetDriverLoadHealthStatus(
	KERNEL_DRIVER_HEALTH_CONTEXT* HealthContext
);