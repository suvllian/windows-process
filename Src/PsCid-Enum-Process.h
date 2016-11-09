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

ULONG_PTR  ulOffset = 0;
ULONG_PTR  ulImageNameOffset = 0;
ULONG_PTR  ObjectHeaderSize = 0;
ULONG_PTR  ObjectTypeOffsetOf_Object_Header = 0;
ULONG_PTR  ObjectTableOffsetOf_EPROCESS = 0;
ULONG      uNum = 0;

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




typedef struct _HANDLE_TABLE_ENTRY64
{
	union {
		PVOID64 Object;
		ULONG ObAttributes;
		PVOID64 InfoTable;
		ULONG_PTR Value;
	};
	union {
		union {
			ULONG GrantedAccess;
			struct {
				USHORT GrantedAccessIndex;
				USHORT CreatorBackTraceIndex;
			};
		};
		ULONG NextFreeTableEntry;
	};

} HANDLE_TABLE_ENTRY64, *PHANDLE_TABLE_ENTRY64;


typedef struct _HANDLE_TABLE_ENTRY32
{
	union {
		PVOID Object;
		ULONG ObAttributes;
		PVOID InfoTable;
		ULONG_PTR Value;
	};
	union {
		union {
			ULONG GrantedAccess;
			struct {
				USHORT GrantedAccessIndex;
				USHORT CreatorBackTraceIndex;
			};
		};
		ULONG NextFreeTableEntry;
	};

} HANDLE_TABLE_ENTRY32, *PHANDLE_TABLE_ENTRY32;

#ifdef _WIN64
#define PHANDLE_TABLE_ENTRY PHANDLE_TABLE_ENTRY64
#else
#define PHANDLE_TABLE_ENTRY PHANDLE_TABLE_ENTRY32
#endif


VOID UnloadDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS DefaultPassThrough(PDEVICE_OBJECT  DeviceObject,PIRP Irp);

WIN_VERSION GetWindowsVersion();
typedef NTSTATUS (*pfnRtlGetVersion)(OUT PRTL_OSVERSIONINFOW lpVersionInformation);
typedef ULONG_PTR (*pfnObGetObjectType)(PVOID Object);
PVOID GetFunctionAddressByName(WCHAR *wzFunction);
NTSTATUS EnumPspCidTable();
ULONG_PTR GetPspCidTableValue();
ULONG_PTR KeGetObjectType(PVOID Object);
BOOLEAN IsProcessDie(PEPROCESS EProcess);
BOOLEAN IsRealProcess(PEPROCESS EProcess);

NTSTATUS EnumTable1(ULONG_PTR ulTableCode);
NTSTATUS EnumTable2(ULONG_PTR ulTableCode);
NTSTATUS EnumTable3(ULONG_PTR ulTableCode);
