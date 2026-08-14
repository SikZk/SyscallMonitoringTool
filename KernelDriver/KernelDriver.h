#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <ntddk.h>

#define MY_POOL_TAG 'Drvk'

typedef struct KERNEL_DRIVER_HEALTH_CONTEXT {
	NTSTATUS LoadImageNotifyRoutineStatus;
};

KERNEL_DRIVER_HEALTH_CONTEXT* KernelDriverHealthContext;

void LoadImageNotifyRoutine(
	UNICODE_STRING* FullImageName,
	HANDLE ProcessId,
	IMAGE_INFO* ImageInfo
);

void MyDriverUnload(PDRIVER_OBJECT DriverObject);