/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include <ntifs.h>


#define DEVICE_NAME  L"\\Device\\PsCid-Enum-ProcessDevice"
#define LINK_NAME    L"\\??\\PsCid-Enum-ProcessLink"

typedef enum WIN_VERSION {
	WINDOWS_UNKNOW,
	WINDOWS_XP,
	WINDOWS_7,
	WINDOWS_8,
	WINDOWS_8_1
} WIN_VERSION;

WIN_VERSION WinVersion = WINDOWS_UNKNOW;

typedef struct _HANDLE_TABLE64
{
	PVOID64 TableCode;
	PVOID64 QuotaProcess;
	PVOID64 UniqueProcessID;
	PVOID64 HandleLock;
	LIST_ENTRY HandleTableList;
	PVOID64    HandleContentionEvent;
	PVOID64    DebugInfo;
	ULONG      ExtraInfoPages;
	ULONG      Flags;
	ULONG      FirstFreeHandle;
	PVOID64    LastFreeHandleEntry;
	ULONG      HandleCount;
	ULONG      NextHandleNeedingPool;
	ULONG      HandleCountHighWatermark;
}HANDLE_TABLE64, *PHANDLE_TABLE64;



typedef struct _HANDLE_TABLE32
{
	PVOID TableCode;
	PVOID QuotaProcess;
	PVOID UniqueProcessID;
	ULONG HandleLock[4];
	LIST_ENTRY HandleTableList;
	PVOID    HandleContentionEvent;
	PVOID    DebugInfo;
	ULONG    ExtraInfoPages;
	ULONG    FirstFree;
	ULONG    LastFree;
	ULONG    NextHandleNeedingPool;
	ULONG    HandleCount;
	ULONG    Flags;
}HANDLE_TABLE32, *PHANDLE_TABLE32;

#ifdef _WIN64
#define PHANDLE_TABLE PHANDLE_TABLE64
#else
#define PHANDLE_TABLE PHANDLE_TABLE32
#endif


VOID UnloadDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS DefaultPassThrough(PDEVICE_OBJECT  DeviceObject,PIRP Irp);

WIN_VERSION GetWindowsVersion();
typedef NTSTATUS (*pfnRtlGetVersion)(OUT PRTL_OSVERSIONINFOW lpVersionInformation);
PVOID GetFunctionAddressByName(WCHAR *wzFunction);
NTSTATUS EnumPspCidTable();

NTSTATUS EnumTable1(ULONG_PTR ulTableCode);
NTSTATUS EnumTable2(ULONG_PTR ulTableCode);
NTSTATUS EnumTable3(ULONG_PTR ulTableCode);
