/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include "PsCid-Enum-Process.h"

NTSTATUS
	DriverEntry(PDRIVER_OBJECT  DriverObject,PUNICODE_STRING  RegisterPath)
{
	PDEVICE_OBJECT  DeviceObject;
	NTSTATUS        Status;
	int             i = 0;
	UNICODE_STRING  DeviceName;
	UNICODE_STRING  LinkName;

	RtlInitUnicodeString(&DeviceName,DEVICE_NAME);
	RtlInitUnicodeString(&LinkName,LINK_NAME);

	//创建设备对象;
	Status = IoCreateDevice(DriverObject,0,
	&DeviceName,FILE_DEVICE_UNKNOWN,0,FALSE,&DeviceObject);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	Status = IoCreateSymbolicLink(&LinkName,&DeviceName);

	for (i = 0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DefaultPassThrough;
	}

	DriverObject->DriverUnload = UnloadDriver;


#ifdef WIN64
	DbgPrint("WIN64: PsCid-Enum-Process IS RUNNING!!!");
#else
	DbgPrint("WIN32: PsCid-Enum-Process SIS RUNNING!!!");
#endif
	
	WinVersion = GetWindowsVersion();

	EnumPspCidTable();

	return STATUS_SUCCESS;
}


WIN_VERSION GetWindowsVersion()
{
	RTL_OSVERSIONINFOEXW OsVerInfo = { sizeof(OsVerInfo) };
	pfnRtlGetVersion RtlGetVersion = NULL;
	WIN_VERSION WinVersion;
	WCHAR wzRtlGetVersion[] = L"RtlGetVersion";

	RtlGetVersion = GetFunctionAddressByName(wzRtlGetVersion);

	if (RtlGetVersion)
	{
		RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVerInfo);
	}
	else
	{
		PsGetVersion(&OsVerInfo.dwMajorVersion, &OsVerInfo.dwMinorVersion, &OsVerInfo.dwBuildNumber, NULL);
	}

	DbgPrint("Build Number:%d\r\n", OsVerInfo.dwBuildNumber);

	if (OsVerInfo.dwMajorVersion == 5 && OsVerInfo.dwMinorVersion == 1)
	{
		DbgPrint("WINDOWS_XP\r\n");
		WinVersion = WINDOWS_XP;
	}
	else if (OsVerInfo.dwMajorVersion == 6 && OsVerInfo.dwMinorVersion == 1)
	{
		DbgPrint("WINDOWS 7\r\n");
		WinVersion = WINDOWS_7;
	}
	else if (OsVerInfo.dwMajorVersion == 6 &&
		OsVerInfo.dwMinorVersion == 2 &&
		OsVerInfo.dwBuildNumber == 9200)
	{
		DbgPrint("WINDOWS 8\r\n");
		WinVersion = WINDOWS_8;
	}
	else if (OsVerInfo.dwMajorVersion == 6 &&
		OsVerInfo.dwMinorVersion == 3 &&
		OsVerInfo.dwBuildNumber == 9600)
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


NTSTATUS EnumPspCidTable()
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG_PTR ulPspCidTable = 0;
	//指向句柄表的指针
	PHANDLE_TABLE HandleTable = NULL;
	ULONG_PTR ulTableCode = 0;
	ULONG ulFlag;

	ulPspCidTable = GetPspCIdTableValue();
	if (ulPspCidTable == 0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	HandleTable = (PHANDLE_TABLE)(*(ULONG_PTR*)ulPspCidTable);
	DbgPrint("HandleTable->%p", HandleTable);


	ulTableCode = (ULONG_PTR)(HandleTable->TableCode) & 0xFFFFFFFFFFFFFFFC;
	ulFlag = (ULONG)(HandleTable->TableCode) & 0x03;
	DbgPrint("uTableCode->%08p", ulTableCode);

	switch (ulFlag)
	{
		case 0:
		{
			EnumTable1(ulTableCode);
			break;
		}
		case 1:
		{
			EnumTable2(ulTableCode);
			break;
		}
		case 2:
		{
			EnumTable3(ulTableCode);
			break;
		}
	}
	return Status;
}

NTSTATUS EnumTable1(ULONG_PTR ulTableCode)
{

}

PVOID GetFunctionAddressByName(WCHAR *wzFunction)
{
	UNICODE_STRING uniFunction;
	PVOID AddressBase = NULL;

	if (wzFunction&&wcslen(wzFunction) > 0)
	{
		RtlInitUnicodeString(&uniFunction, wzFunction);
		AddressBase = MmGetSystemRoutineAddress(&uniFunction);
	}

	return AddressBase;
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

	DbgPrint("PsCid-Enum-Process IS STOPPED!!!");
}