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

	ulPspCidTable = GetPspCidTableValue();
	if (ulPspCidTable == 0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	HandleTable = (PHANDLE_TABLE)(*(ULONG_PTR*)ulPspCidTable);
	DbgPrint("HandleTable->%p", HandleTable);


	ulTableCode = (ULONG_PTR)(HandleTable->TableCode) & 0xFFFFFFFFFFFFFFFC;
	//TableCode和11(2)进行与运算 
	//三种情况：1、00一层表
	//2、01两层表
	//3、10三层表
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

ULONG_PTR GetPspCidTableValue()
{
	PVOID PsLookupProcessByProcessIdAddress = NULL;
	ULONG_PTR ulPspCidTableValue = 0;
	UNICODE_STRING uniFuncName;
	ULONG uIndex = 0;
	int Offset = 0;


	RtlInitUnicodeString(&uniFuncName, L"PsLookupProcessByProcessId");
	PsLookupProcessByProcessIdAddress = MmGetSystemRoutineAddress(&uniFuncName);
	if (PsLookupProcessByProcessIdAddress == NULL)
	{
		return ulPspCidTableValue;
	}

	DbgPrint("PsLookupProcessByProcessId->%08X", PsLookupProcessByProcessIdAddress);


	switch (WinVersion)
	{
		case WINDOWS_7:
			{
			/*
			kd> u PsLookupProcessByProcessId l 20
			nt!PsLookupProcessByProcessId:
			fffff800`041a61fc 48895c2408      mov     qword ptr [rsp+8],rbx
			fffff800`041a6201 48896c2410      mov     qword ptr [rsp+10h],rbp
			fffff800`041a6206 4889742418      mov     qword ptr [rsp+18h],rsi
			fffff800`041a620b 57              push    rdi
			fffff800`041a620c 4154            push    r12
			fffff800`041a620e 4155            push    r13
			fffff800`041a6210 4883ec20        sub     rsp,20h
			fffff800`041a6214 65488b3c2588010000 mov   rdi,qword ptr gs:[188h]
			fffff800`041a621d 4533e4          xor     r12d,r12d
			fffff800`041a6220 488bea          mov     rbp,rdx
			fffff800`041a6223 66ff8fc4010000  dec     word ptr [rdi+1C4h]
			fffff800`041a622a 498bdc          mov     rbx,r12
			fffff800`041a622d 488bd1          mov     rdx,rcx
			fffff800`041a6230 488b0d9149edff  mov     rcx,qword ptr [nt!PspCidTable (fffff800`0407abc8)]
			fffff800`041a6237 e834480200      call    nt!ExMapHandleToPointer (fffff800`041caa70)
			*/

				ulOffset = 0x10;
				ulImageNameOffset = 0x2e0;
				ObjectTableOffsetOf_EPROCESS = 0X200;
				ObjectHeaderSize = 0x30;
				//使用特征码进行判断
				for (uIndex = 0; uIndex < 0x1000; uIndex++)
				{
					if (*((PUCHAR)((ULONG_PTR)PsLookupProcessByProcessIdAddress + uIndex)) == 0x48 &&
						*((PUCHAR)((ULONG_PTR)PsLookupProcessByProcessIdAddress + uIndex + 1)) == 0x8B &&
						*((PUCHAR)((ULONG_PTR)PsLookupProcessByProcessIdAddress + uIndex + 7)) == 0xE8)
					{

						memcpy(&Offset, (PUCHAR)((ULONG_PTR)PsLookupProcessByProcessIdAddress + uIndex + 3), 4);
						ulPspCidTableValue = (ULONG_PTR)PsLookupProcessByProcessIdAddress + uIndex + Offset + 7;

						DbgPrint("Found OK!!\r\n");
						break;
					}
				}
				break;
			}
		case WINDOWS_XP:
		{
			/*
			kd> u PsLookupProcessByProcessId l 20
			nt!PsLookupProcessByProcessId:
			80582687 8bff            mov     edi,edi
			80582689 55              push    ebp
			8058268a 8bec            mov     ebp,esp
			8058268c 53              push    ebx
			8058268d 56              push    esi
			8058268e 64a124010000    mov     eax,dword ptr fs:[00000124h]
			80582694 ff7508          push    dword ptr [ebp+8]
			80582697 8bf0            mov     esi,eax
			80582699 ff8ed4000000    dec     dword ptr [esi+0D4h]
			8058269f ff3560a75680    push    dword ptr [nt!PspCidTable (8056a760)]

			*/

			ulOffset = 0x8;
			ulImageNameOffset = 0x174;
			ObjectTypeOffsetOf_Object_Header = 0x8;
			ObjectTableOffsetOf_EPROCESS = 0x0c4;
			ObjectHeaderSize = 0x18;

			for (uIndex = 0; uIndex < 0x1000; uIndex++)
			{
				if (*((PUCHAR)((ULONG_PTR)PsLookupProcessByProcessIdAddress + uIndex)) == 0xFF &&
					*((PUCHAR)((ULONG_PTR)PsLookupProcessByProcessIdAddress + uIndex + 1)) == 0x35 &&
					*((PUCHAR)((ULONG_PTR)PsLookupProcessByProcessIdAddress + uIndex + 6)) == 0xE8)
				{
					DbgPrint("Found OK!!\r\n");
					ulPspCidTableValue = *((PULONG)((ULONG)PsLookupProcessByProcessIdAddress + uIndex + 2));
					break;
				}
			}
			break;
		}
	}
	return ulPspCidTableValue;
}

NTSTATUS EnumTable1(ULONG_PTR ulTableCode)
{
	PHANDLE_TABLE_ENTRY HandleTableEntry = NULL;
	ULONG uIndex = 0;
	HandleTableEntry = (PHANDLE_TABLE_ENTRY)((ULONG_PTR)(*(ULONG_PTR*)ulTableCode) + ulOffset);

	for (uIndex = 0; uIndex < 0x200; uIndex++)
	{
		if (MmIsAddressValid((PVOID)&(HandleTableEntry->NextFreeTableEntry)))
		{
			if (HandleTableEntry->NextFreeTableEntry == 0)
			{
				if (HandleTableEntry->Object != NULL)
				{
					if (MmIsAddressValid(HandleTableEntry->Object))
					{
						PEPROCESS CurEProcess = (PEPROCESS)(((ULONG_PTR)HandleTableEntry->Object) & 0xFFFFFFFFFFFFFFF8);
						if (IsRealProcess(CurEProcess))
						{
							uNum++;
							DbgPrint("Num:%d   CurEProcess->%p----%s\r\n", uNum, CurEProcess, (PUCHAR)CurEProcess + ulImageNameOffset);
						}
					}
				}
			}
		}
		HandleTableEntry++;
	}

	return STATUS_SUCCESS;
}


NTSTATUS EnumTable2(ULONG_PTR ulTableCode)
{
	do
	{
		EnumTable1(ulTableCode);
		ulTableCode += sizeof(ULONG_PTR);

	} while (*(PULONG_PTR)ulTableCode != 0 && MmIsAddressValid((PVOID)*(PULONG_PTR)ulTableCode));

	return STATUS_SUCCESS;
}


NTSTATUS  EnumTable3(ULONG_PTR ulTableCode)
{
	do
	{
		EnumTable2(ulTableCode);
		ulTableCode += sizeof(ULONG_PTR);

	} while (*(PULONG_PTR)ulTableCode != 0);

	return STATUS_SUCCESS;
}


BOOLEAN IsRealProcess(PEPROCESS EProcess)
{
	ULONG_PTR ObjectType;
	ULONG_PTR ObjectTypeAddress;
	BOOLEAN bRet = FALSE;

	ULONG_PTR ProcessType = ((ULONG_PTR)*PsProcessType);

	if (ProcessType&&MmIsAddressValid&&EProcess&&MmIsAddressValid((PVOID)(EProcess)))
	{
		ObjectType = KeGetObjectType((PVOID)EProcess);
		if (ObjectType&&ProcessType == ObjectType && !IsProcessDie(EProcess))
		{
			bRet = TRUE;
		}
	}

	return bRet;
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



ULONG_PTR KeGetObjectType(PVOID Object)
{
	ULONG_PTR ObjectType = NULL;
	pfnObGetObjectType ObGetObjectType= NULL;

	if (!MmIsAddressValid || !Object || !MmIsAddressValid(Object))
	{
		return NULL;
	}

	if (WinVersion == WINDOWS_XP)
	{
		ULONG SizeOfObjectHeader = 0, ObjectTypeOffset = 0, ObjectTypeAddress = 0;
		ObjectTypeAddress = (ULONG_PTR)Object - ObjectHeaderSize + ObjectTypeOffsetOf_Object_Header;

		if (MmIsAddressValid((PVOID)ObjectTypeAddress))
		{
			ObjectType = *(ULONG_PTR*)ObjectTypeAddress;
		}
	}

	if (WinVersion == WINDOWS_7)
	{
		//高版本使用函数

		ObGetObjectType = (pfnObGetObjectType)GetFunctionAddressByName(L"ObGetObjectType");


		if (ObGetObjectType)
		{
			ObjectType = ObGetObjectType(Object);
		}
	}

	return ObjectType;
}

BOOLEAN IsProcessDie(PEPROCESS EProcess)
{
	BOOLEAN bDie = FALSE;

	if (MmIsAddressValid&&EProcess&&MmIsAddressValid(EProcess) &&
		MmIsAddressValid((PVOID)((ULONG_PTR)EProcess + ObjectTableOffsetOf_EPROCESS)))
	{
		PVOID ObjectTable = *(PVOID*)((ULONG_PTR)EProcess + ObjectTableOffsetOf_EPROCESS);

		if (!ObjectTable || !MmIsAddressValid(ObjectTable))
		{
			DbgPrint("Process is Die\r\n");
			bDie = TRUE;
		}
	}

	else
	{
		bDie = TRUE;
	}

	return bDie;
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