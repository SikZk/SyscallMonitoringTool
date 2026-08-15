#pragma once
#include <ntifs.h>

#define MY_POOL_TAG 'Drvk'

struct KERNEL_DRIVER_HEALTH_CONTEXT {
	NTSTATUS LoadImageNotifyRoutineStatus;
};

struct KERNEL_DRIVER_DATA {
	void*	LdrLoadDllAddress;
	UNICODE_STRING 	MonitoringDllPath;
};

extern KERNEL_DRIVER_HEALTH_CONTEXT* KernelDriverHealthContext;
extern KERNEL_DRIVER_DATA* KernelDriverData;

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

NTSTATUS InitializeKernelDriverStructures();

void FreeKernelDriverStructures();