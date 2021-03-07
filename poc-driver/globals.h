#ifndef GLOBALS_H
#define GLOBALS_H

#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <windows.h>
#include <winternl.h>
typedef struct _CLIENT_ID *PCLIENT_ID;
typedef void *PKSTART_ROUTINE;
typedef void *PEPROCESS;
#endif

// #define OLD_WINDOWS

PLIST_ENTRY _PsInitialSystemProcess;
NTSTATUS(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);


#ifdef _KERNEL_MODE
NTSTATUS(NTAPI* _KeDelayExecutionThread)(KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER);
NTSTATUS(NTAPI* _PsCreateSystemThread)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID);
PVOID(__fastcall* _MmMapIoSpace)(QWORD, SIZE_T, MEMORY_CACHING_TYPE);
VOID(__fastcall* _MmUnmapIoSpace)(PVOID, SIZE_T);
NTSTATUS(__fastcall* _MmCopyMemory)(PVOID, SIZE_T, SIZE_T, ULONG, SIZE_T*);
PCSTR(*_PsGetProcessImageFileName)(PEPROCESS);
BOOLEAN(*_PsGetProcessExitProcessCalled)(PEPROCESS);
PVOID(*_PsGetProcessWow64Process)(PEPROCESS);
PVOID(*_PsGetProcessPeb)(PEPROCESS);
ULONG(*_PsGetProcessSessionId)(PEPROCESS);
ULONG(NTAPI* _RtlRandomEx)(_Inout_ PULONG);
LARGE_INTEGER(NTAPI*_KeQueryPerformanceCounter)(PLARGE_INTEGER);
PVOID(__fastcall* _ExAllocatePoolWithTag)(POOL_TYPE, SIZE_T, unsigned int);
VOID(__fastcall* _ExFreePoolWithTag)(PVOID, ULONG);


ULONG
(__cdecl *
_DbgPrint) (
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );

NTSTATUS (NTAPI *_ObReferenceObjectByName)(
	_In_ PUNICODE_STRING ObjectName,
	_In_ ULONG Attributes,
	_In_opt_ PACCESS_STATE AccessState,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Inout_opt_ PVOID ParseContext,
	_Out_ PVOID* Object
);

POBJECT_TYPE* _IoDriverObjectType;

PIRP (__stdcall *_IoBuildDeviceIoControlRequest)(
    _In_  ULONG IoControlCode,
    _In_  PDEVICE_OBJECT DeviceObject,
    _In_opt_  PVOID InputBuffer,
    _In_  ULONG InputBufferLength,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _In_ BOOLEAN InternalDeviceIoControl,
    _In_opt_ PKEVENT Event,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock
    );

NTSTATUS (__fastcall *_IofCallDriver)(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ __drv_aliasesMem PIRP Irp
    );

PVOID(__stdcall* _PsGetThreadId)(PVOID);

NTSTATUS(__stdcall*_PsLookupThreadByThreadId)(
	_In_ HANDLE ThreadId,
	_Outptr_ PETHREAD* Thread
	);

__int64(__fastcall* _ExDestroyHandle)(__int64 a1, __int64 a2, __int64 a3);
volatile signed __int64* (__fastcall* _ExMapHandleToPointer)(unsigned int* a1, __int64 a2);
unsigned int (* _PsGetThreadExitStatus)(__int64 a1);
NTSTATUS(NTAPI* _ZwClose)(HANDLE);

extern DWORD       g_encryption_key;
extern ULONG_PTR   g_PsTerminatedThread;
extern ULONG       g_PsGetThreadIdOffset;
extern ULONG       g_PsActiveProcessLink;
extern PLIST_ENTRY g_PsThreadListEntry;

#endif

#endif

