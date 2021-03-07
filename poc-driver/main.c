#include <ntifs.h>
#include "crc32.h"
#include "globals.h"

#define MAPPER_SIZE 14 + 7
#define MAPPER_BASE MAPPER_SIZE
__declspec(dllexport) volatile BYTE qwerty[MAPPER_SIZE + 16];

DWORD       g_encryption_key = 0x726D0100;


BOOL LoadExports(PDRIVER_OBJECT driver);
QWORD GetSystemBaseAddressQ(PDRIVER_OBJECT DriverObject, DWORD crc, DWORD crc_len);
BOOLEAN MemCopyWP(PVOID dest, PVOID src, ULONG length);
QWORD ResolveEntryAddress(PDRIVER_OBJECT driver);
void clear_pe_header(QWORD map_driver_base);

void NtSleep(DWORD milliseconds)
{
#ifdef _KERNEL_MODE
	QWORD ms = milliseconds;
	ms = (ms * 1000) * 10;
	ms = ms * -1;
	_KeDelayExecutionThread(KernelMode, 0, (PLARGE_INTEGER)&ms);
#else
	QWORD ms = milliseconds;
	ms = (ms * 1000) * 10;
	ms = ms * -1;


	Sleep(milliseconds);
#endif
}

void NotifyRoutine(void)
{
	while (1) {
		NtSleep(50);
		_DbgPrint("[+] called from TID: %ld\n", _PsGetThreadId((PVOID)__readgsqword(0x188)));
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
	NTSTATUS ( *func )(
	    _In_ struct _DRIVER_OBJECT *DriverObject,
	    _In_ PUNICODE_STRING RegistryPath
	    );

	if (!LoadExports(driver)) {
		/* fail to load exports, cause bluescreen */
		*(int*)(0x10A0) = 0;
	}

	*(QWORD*)&func = ResolveEntryAddress(driver);
	if (func == 0)
		*(int*)(0x10A0) = 0;

	if (!MemCopyWP((PVOID)func, (PVOID)qwerty, MAPPER_SIZE)) {
		/* fail to load fix entry, cause bluescreen */
		*(int*)(0x10A0) = 0;
	}
	
	QWORD current_driver_base = *(QWORD*)((char*)qwerty + MAPPER_BASE);
	clear_pe_header(current_driver_base);

	HANDLE thread;
	CLIENT_ID threadid;
	_PsCreateSystemThread(&thread, STANDARD_RIGHTS_ALL, NULL, NULL, &threadid, (PKSTART_ROUTINE)NotifyRoutine, (PVOID)0);
	_ZwClose(thread);

	return func(driver, registryPath);
}

QWORD GetProcAddressQ(QWORD base, DWORD crc, DWORD length)
{
	QWORD a0;
	DWORD a1[4];

	a0 = base + *(USHORT*)(base + 0x3C);
	a0 = base + *(DWORD*)(a0 + 0x88);
	a1[0] = *(DWORD*)(a0 + 0x18);
	a1[1] = *(DWORD*)(a0 + 0x1C);
	a1[2] = *(DWORD*)(a0 + 0x20);
	a1[3] = *(DWORD*)(a0 + 0x24);
	while (a1[0]--) {
		a0 = base + *(DWORD*)(base + a1[2] + (a1[0] * 4));
		if (crc32((PCSTR)a0, length, g_encryption_key) == crc) {
			return (base + *(DWORD*)(base + a1[1] +
				(*(USHORT*)(base + a1[3] + (a1[0] * 2)) * 4)));
		}
	}
	return 0;
}

#define CRC32_EXPORT(var, crc, crc_length) \
	*(QWORD*)&var = GetProcAddressQ(ntosrknl_base, crc, crc_length); \
	if (var == 0) return 0; \

#define CRC32_EXPORT_HAL(var, crc, crc_length) \
	*(QWORD*)&var = GetProcAddressQ(hal_base, crc, crc_length); \
	if (var == 0) return 0; \


PMDL(*_IoAllocateMdl)(
	_In_opt_ __drv_aliasesMem PVOID VirtualAddress,
	_In_ ULONG Length,
	_In_ BOOLEAN SecondaryBuffer,
	_In_ BOOLEAN ChargeQuota,
	_Inout_opt_ PIRP Irp
	);

VOID(*_MmProbeAndLockPages)(
	_Inout_ PMDL MemoryDescriptorList,
	_In_ KPROCESSOR_MODE AccessMode,
	_In_ LOCK_OPERATION Operation
	);

PVOID
(*_MmMapLockedPagesSpecifyCache)(
	_Inout_ PMDL MemoryDescriptorList,
	_In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst)
	KPROCESSOR_MODE AccessMode,
	_In_ __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType,
	_In_opt_ PVOID RequestedAddress,
	_In_     ULONG BugCheckOnFailure,
	_In_     ULONG Priority  // MM_PAGE_PRIORITY logically OR'd with MdlMapping*

	);

VOID
(*_MmUnlockPages)(
	_Inout_ PMDL MemoryDescriptorList
	);

VOID
(*_IoFreeMdl)(
	PMDL Mdl
	);

VOID
(*_MmUnmapLockedPages)(
	_In_ PVOID BaseAddress,
	_Inout_ PMDL MemoryDescriptorList
	);

void* (__cdecl* _memcpy)(_Out_writes_bytes_all_(_MaxCount) void* _Dst, _In_reads_bytes_(_MaxCount) const void* _Src, _In_ size_t _MaxCount);

BOOL LoadExports(PDRIVER_OBJECT driver)
{
	QWORD ntosrknl_base = GetSystemBaseAddressQ(driver, 0x59f44bf0, 26);
#ifdef _KERNEL_MODE
	CRC32_EXPORT(_PsInitialSystemProcess, 0xf5acb841, 23);
#endif
	CRC32_EXPORT(_RtlInitUnicodeString, 0x93970a42, 21);
	CRC32_EXPORT(_ZwClose, 0x78e9da22, 8);
#ifdef _KERNEL_MODE
	CRC32_EXPORT(_KeDelayExecutionThread, 0x6be39931, 23);
	CRC32_EXPORT(_PsCreateSystemThread, 0xa7342b8a, 21);
	CRC32_EXPORT(_MmMapIoSpace, 0xe3e97fc8, 13);
	CRC32_EXPORT(_MmUnmapIoSpace, 0x61dd59d8, 15);
	CRC32_EXPORT(_MmCopyMemory, 0x447b9e0c, 13);
	CRC32_EXPORT(_RtlRandomEx, 0x212bf249, 12);
	CRC32_EXPORT(_DbgPrint, 0xbb9e4a14, 9);
	CRC32_EXPORT(_ExAllocatePoolWithTag, 0x3d274aca, 22);
	CRC32_EXPORT(_ExFreePoolWithTag, 0xbf55cf42, 18);
	CRC32_EXPORT(_IoDriverObjectType, 0x4929b432, 19);
	CRC32_EXPORT(_ObReferenceObjectByName, 0xb4cde7b1, 24);
	CRC32_EXPORT(_IoBuildDeviceIoControlRequest, 0x486b6f47, 30);
	CRC32_EXPORT(_IofCallDriver, 0x2bfbfcc3, 14);
	CRC32_EXPORT(_PsGetThreadId, 0xb0fd823, 14);
	CRC32_EXPORT(_PsLookupThreadByThreadId, 0xff312af1, 25);
	CRC32_EXPORT(_IoAllocateMdl, 0x16833110, 14);
	CRC32_EXPORT(_MmProbeAndLockPages, 0xbc7855a4, 20);
	CRC32_EXPORT(_MmMapLockedPagesSpecifyCache, 0xd7bc7957, 29);
	CRC32_EXPORT(_MmUnlockPages, 0x85af60ed, 14);
	CRC32_EXPORT(_IoFreeMdl, 0xd0afdf3e, 10);
	CRC32_EXPORT(_MmUnmapLockedPages, 0xb38e8b38, 19);
	CRC32_EXPORT(_memcpy, 0xe2003a33, 7);
	CRC32_EXPORT(_PsGetThreadExitStatus, 0x981a33d, 22);
#endif

	return 1;
}

BOOLEAN MemCopyWP(PVOID dest, PVOID src, ULONG length)
{
	PMDL mdl = _IoAllocateMdl(dest, length, FALSE, FALSE, NULL);
	if (!mdl) {
		return FALSE;
	}

	_MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

	PVOID mapped = _MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, 0, HighPagePriority);
	if (!mapped) {
		_MmUnlockPages(mdl);
		_IoFreeMdl(mdl);
		return FALSE;
	}

	_memcpy(mapped, src, length);

	_MmUnmapLockedPages(mapped, mdl);
	_MmUnlockPages(mdl);
	_IoFreeMdl(mdl);
	return TRUE;
}

#pragma warning(disable : 4201)
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

QWORD GetSystemBaseAddressQ(PDRIVER_OBJECT DriverObject, DWORD crc, DWORD crc_len)
{
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	for (PLIST_ENTRY pListEntry = ldr->InLoadOrderLinks.Flink; pListEntry != &ldr->InLoadOrderLinks; pListEntry = pListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (pEntry->BaseDllName.Buffer && crc32((PCSTR)pEntry->BaseDllName.Buffer, crc_len, g_encryption_key) == crc) {
			return (QWORD)pEntry->DllBase;
		}

	}
	return 0;
}

#ifdef _KERNEL_MODE
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[8];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#endif
QWORD ResolveEntryAddress(PDRIVER_OBJECT driver)
{
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)driver->DriverSection;
	// ldr->DllBase

	unsigned char *ldr_base = (unsigned char* )ldr->DllBase;

        IMAGE_NT_HEADERS64* ntHeaders =
                (IMAGE_NT_HEADERS64*)(ldr_base +
                        ((IMAGE_DOS_HEADER*)ldr_base)->e_lfanew);

	return (QWORD)(ldr_base + ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

void clear_pe_header(QWORD map_driver_base)
{
	IMAGE_NT_HEADERS64* nt_headers =
		(IMAGE_NT_HEADERS64*)(map_driver_base +
			((IMAGE_DOS_HEADER*)map_driver_base)->e_lfanew);

	for (DWORD i = nt_headers->OptionalHeader.SizeOfHeaders; i--;)
		((unsigned char*)map_driver_base)[i] = 0;
}
