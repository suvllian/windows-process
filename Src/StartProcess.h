/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include <ntifs.h>

#ifndef CXX_StartProcess_H
#define CXX_StartProcess_H

#define DEVICE_NAME  L"\\Device\\StartProcessDevice"
#define LINK_NAME    L"\\??\\StartProcessLink"


typedef
NTSTATUS
(*pfnRtlGetVersion)(OUT PRTL_OSVERSIONINFOW lpVersionInformation);

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment
} KAPC_ENVIRONMENT;

typedef enum WIN_VERSION {
	WINDOWS_UNKNOW,
	WINDOWS_XP,
	WINDOWS_7,
	WINDOWS_8,
	WINDOWS_8_1
} WIN_VERSION;

NTKERNELAPI
VOID
KeInitializeApc(
	IN PRKAPC Apc,
	IN PKTHREAD Thread,
	IN KAPC_ENVIRONMENT Environment,
	IN PKKERNEL_ROUTINE KernelRoutine,
	IN PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
	IN PKNORMAL_ROUTINE NormalRoutine OPTIONAL,
	IN KPROCESSOR_MODE ApcMode,
	IN PVOID NormalContext
);


NTKERNELAPI
BOOLEAN
KeInsertQueueApc(
	IN PRKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY Increment
);

UCHAR ShellCode[] = {
	0xB8,0xAD,0x23,0x86,
	0x7C,0x6A,0x01,0x90,
	0x68,0x56,0x23,0x00,
	0x00,0xFF,0xD0,0xEB,
	0x0A,0x90,0x90,0x90,
	0x90,0x90,0x90,0x90,
	0x90,0x90,0x90,0x90,
	0xC2,0x00,0x00 };

WIN_VERSION WinVersion;
ULONG_PTR	ThreadListHead = 0;
ULONG_PTR	ThreadListEntry = 0;
ULONG_PTR	Alertable = 0;
PMDL	Mdl = NULL;

VOID UnloadDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS DefaultPassThrough(PDEVICE_OBJECT  DeviceObject,PIRP Irp);

extern HANDLE PsGetThreadId(PETHREAD Thread);
extern UCHAR*	PsGetProcessImageFileName(PEPROCESS EProcess);
PEPROCESS FindEProcessByName(char* szProcessName, ULONG_PTR nLen);
VOID InitGlobalVariable();
WIN_VERSION GetWindowsVersion();
PVOID	GetFunctionAddressByName(WCHAR *szFunction);
VOID GetValidApc(CHAR* ProcessPath, PEPROCESS EProcess);
NTSTATUS InstallUserModeApc(LPSTR ProcessPath, PKTHREAD TargetThread, PEPROCESS TargetProcess);
VOID ApcKernelRoutine(IN struct _KAPC *Apc, IN OUT PKNORMAL_ROUTINE *NormalRoutine,
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1, IN OUT PVOID *SystemArgument2);

#endif