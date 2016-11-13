/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include "StartProcess.h"

NTSTATUS
	DriverEntry(PDRIVER_OBJECT  DriverObject,PUNICODE_STRING  RegisterPath)
{
	PEPROCESS EProcess = NULL;

	InitGlobalVariable();

	EProcess = FindEProcessByName("explore.exe", 12);
	if (EProcess == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	GetValidApc("D:\\1.exe", EProcess);

	DbgPrint("%p\r\n", EProcess);

	DriverObject->DriverUnload = UnloadDriver;
#ifdef WIN64
	DbgPrint("WIN64: StartProcess IS RUNNING!!!");
#else
	DbgPrint("WIN32: StartProcess SIS RUNNING!!!");
#endif
	
	return STATUS_SUCCESS;
}

VOID GetValidApc(CHAR* ProcessPath, PEPROCESS EProcess)
{
	PLIST_ENTRY ListTemp = NULL;
	PLIST_ENTRY ListHead = NULL;
	BOOLEAN bOk = FALSE;
	PETHREAD EThread = NULL;
	ULONG_PTR  Temp = 0;


	ListHead = (PLIST_ENTRY)((ULONG_PTR)EProcess + ThreadListHead);
	ListTemp = ListHead->Flink;

	while (ListTemp != ListHead)
	{
		EThread = (PETHREAD)((ULONG_PTR)ListTemp - ThreadListEntry);

		switch (WinVersion)
		{
			case WINDOWS_XP:
			{
				if (*((UCHAR*)((ULONG_PTR)EThread + Alertable)))
				{
					DbgPrint("Success\r\n");
					bOk = TRUE;
					break;
				}
				break;
			}

			case WINDOWS_7:
			{
				Temp = *((ULONG_PTR*)(((ULONG_PTR)EThread + Alertable)));
				if (Temp & 0x20)
				{
					bOk = TRUE;
					DbgPrint("Success\r\n");
					break;
				}
				break;
			}
		}

		if (bOk == TRUE)
		{
			InstallUserModeApc(ProcessPath, EThread, EProcess);
			break;
		}
		else
		{
			//线程体下移
			ListTemp = ListTemp->Flink;
		}
	}
}

NTSTATUS InstallUserModeApc(LPSTR ProcessPath, PKTHREAD TargetThread, PEPROCESS TargetProcess)
{
	PRKAPC Apc = NULL;
	PVOID MappedAddress = NULL;
	ULONG_PTR dwSize = 0;
	KAPC_STATE ApcState;

	ULONG* Address = 0;

	if (!TargetThread || !TargetProcess)
	{
		return STATUS_UNSUCCESSFUL;
	}

	Apc = ExAllocatePool(NonPagedPool, sizeof(KAPC));
	if (!Apc)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	dwSize = sizeof(ShellCode);

	Mdl = IoAllocateMdl(ShellCode, dwSize, FALSE, FALSE, NULL);
	if (!Mdl)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(Mdl);
		ExFreePool(Apc);
		return STATUS_UNSUCCESSFUL;
	}

	KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);
	MappedAddress = MmMapLockedPagesSpecifyCache(Mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);

	if (!MappedAddress)
	{
		KeUnstackDetachProcess(&ApcState);
		IoFreeMdl(Mdl);
		ExFreePool(Apc);

		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("ShellCode\r\n");

	memset((unsigned char*)MappedAddress + 0x11, 0, 0x0A);
	memcpy((unsigned char*)MappedAddress + 0x11,
		ProcessPath, strlen(ProcessPath));

	Address = (ULONG*)((char*)MappedAddress + 0x9);
	*Address = ((char*)MappedAddress) + 0x11;

	KeUnstackDetachProcess(&ApcState);

	KeInitializeApc(Apc, TargetThread,
		OriginalApcEnvironment,
		&ApcKernelRoutine, NULL,
		MappedAddress, UserMode, (PVOID)NULL);

	if (!KeInsertQueueApc(Apc, 0, NULL, 0))
	{
		DbgPrint("Error1\r\n");
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);
		ExFreePool(Apc);
		return STATUS_UNSUCCESSFUL;
	}

	if (!(*((char*)((ULONG)TargetThread + 0x34 + 0x16))))
	{
		DbgPrint("True\r\n");
		*((char*)((ULONG)TargetThread + 0x34 + 0x16)) = TRUE;
	}

	return STATUS_SUCCESS;
}

VOID ApcKernelRoutine(IN struct _KAPC *Apc, IN OUT PKNORMAL_ROUTINE *NormalRoutine,
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1, IN OUT PVOID *SystemArgument2)
{

	if (Apc)
		ExFreePool(Apc);
	if (Mdl)
	{
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);
		Mdl = NULL;
	}

}

//通过 函数名称 得到函数地址
PVOID GetFunctionAddressByName(WCHAR *szFunction)
{
	UNICODE_STRING uniFunction;
	PVOID AddrBase = NULL;

	if (szFunction && wcslen(szFunction) > 0)
	{
		RtlInitUnicodeString(&uniFunction, szFunction);   //常量指针
		AddrBase = MmGetSystemRoutineAddress(&uniFunction);
	}

	return AddrBase;
}

PEPROCESS FindEProcessByName(char* szProcessName, ULONG_PTR nLen)
{
	NTSTATUS Status;
	ULONG_PTR i = 0;
	PEPROCESS EProcess;
	char* szProcessNameTemp;

	for (i = 0; i < 100000; i += 4)
	{
		Status = PsLookupProcessByProcessId((HANDLE)i, &EProcess);
		if (Status == STATUS_SUCCESS)
		{
			ObDereferenceObject(EProcess);	

			szProcessNameTemp = PsGetProcessImageFileName(EProcess);

			if (!_strnicmp(szProcessNameTemp, szProcessName, nLen))
			{
				return EProcess;
			}
		}
	}

	return NULL;
}

VOID InitGlobalVariable()
{
	WinVersion = GetWindowsVersion();
	switch (WinVersion)
	{
	case WINDOWS_7:
	{
		ThreadListHead = 0x308;
		Alertable = 0x4c;	//5位
		ThreadListEntry = 0x420;
		break;
	}
	case WINDOWS_XP:
	{
		ThreadListEntry = 0x22c;
		Alertable = 0x164;
		ThreadListHead = 0x190;
		break;
	}
	}
}

NTSTATUS DefaultPassThrough(PDEVICE_OBJECT  DeviceObject,PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING  LinkName;
	PDEVICE_OBJECT	NextDeviceObject    = NULL;
	PDEVICE_OBJECT  CurrentDeviceObject = NULL;
	RtlInitUnicodeString(&LinkName,LINK_NAME);

	IoDeleteSymbolicLink(&LinkName);
	CurrentDeviceObject = DriverObject->DeviceObject;
	while (CurrentDeviceObject != NULL) 
	{
	
		NextDeviceObject = CurrentDeviceObject->NextDevice;
		IoDeleteDevice(CurrentDeviceObject);
		CurrentDeviceObject = NextDeviceObject;
	}
	DbgPrint("StartProcess IS STOPPED!!!");
}

WIN_VERSION GetWindowsVersion()
{
	RTL_OSVERSIONINFOEXW osverInfo = { sizeof(osverInfo) };
	pfnRtlGetVersion RtlGetVersion = NULL;
	WIN_VERSION WinVersion;
	WCHAR szRtlGetVersion[] = L"RtlGetVersion";

	RtlGetVersion = GetFunctionAddressByName(szRtlGetVersion);

	if (RtlGetVersion)
	{
		RtlGetVersion((PRTL_OSVERSIONINFOW)&osverInfo);
	}
	else
	{
		PsGetVersion(&osverInfo.dwMajorVersion, &osverInfo.dwMinorVersion, &osverInfo.dwBuildNumber, NULL);
	}

	DbgPrint("Build Number: %d\r\n", osverInfo.dwBuildNumber);

	if (osverInfo.dwMajorVersion == 5 && osverInfo.dwMinorVersion == 1)
	{
		DbgPrint("WINDOWS_XP\r\n");
		WinVersion = WINDOWS_XP;
	}
	else if (osverInfo.dwMajorVersion == 6 && osverInfo.dwMinorVersion == 1)
	{
		DbgPrint("WINDOWS 7\r\n");
		WinVersion = WINDOWS_7;
	}
	else if (osverInfo.dwMajorVersion == 6 &&
		osverInfo.dwMinorVersion == 2 &&
		osverInfo.dwBuildNumber == 9200)
	{
		DbgPrint("WINDOWS 8\r\n");
		WinVersion = WINDOWS_8;
	}
	else if (osverInfo.dwMajorVersion == 6 &&
		osverInfo.dwMinorVersion == 3 &&
		osverInfo.dwBuildNumber == 9600)
	{
		DbgPrint("WINDOWS 8.1\r\n");
		WinVersion = WINDOWS_8_1;
	}
	else
	{
		DbgPrint("WINDOWS_UNKNOW\r\n");
		WinVersion = WINDOWS_UNKNOW;
	}

	return WinVersion;
}
