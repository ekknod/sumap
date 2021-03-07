#include "stdafx.h"

/*
 * project based on umap
 * - load driver for extended signed driver ( MICROCODE driver ) address space
 * - load driver from USB filesystem
 * - (map driver must have enough zeroes at end, correct binary size: ~10-25KB for bug free load)
 * - :waving: FACEIT AC team
 */

CHAR8* gEfiCallerBaseName = "";
UINT32 _gUefiDriverRevision = 0;

EFI_EXIT_BOOT_SERVICES ExitBootServicesOriginal;
UINT8 ImgArchStartBootApplicationOriginal[JMP_SIZE];
IMG_ARCH_START_BOOT_APPLICATION ImgArchStartBootApplication;

UINT8 BlImgAllocateImageBufferOriginal[JMP_SIZE];
BL_IMG_ALLOCATE_IMAGE_BUFFER BlImgAllocateImageBuffer;

UINT8 OslFwpKernelSetupPhase1Original[JMP_SIZE];
OSL_FWP_KERNEL_SETUP_PHASE_1 OslFwpKernelSetupPhase1;

struct {
        VOID* Base;
        UINT32 Size;
        CHAR16* ProtectedModeError;
        EFI_STATUS ProtectedModeStatus;
} winload = { NULL };


struct {
    VOID *AllocatedBuffer;
    EFI_STATUS AllocatedBufferStatus;
} mapper = { NULL };

#define EFI_FILE_INFO_ID \
   { \
     0x9576e92, 0x6d3f, 0x11d2, {0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } \
   }

typedef struct {
        ///
        /// The size of the EFI_FILE_INFO structure, including the Null-terminated FileName string.
        ///
        UINT64    Size;
        ///
        /// The size of the file in bytes.
        ///
        UINT64    FileSize;
        ///
        /// PhysicalSize The amount of physical space the file consumes on the file system volume.
        ///
        UINT64    PhysicalSize;
        ///
        /// The time the file was created.
        ///
        EFI_TIME  CreateTime;
        ///
        /// The time when the file was last accessed.
        ///
        EFI_TIME  LastAccessTime;
        ///
        /// The time when the file's contents were last modified.
        ///
        EFI_TIME  ModificationTime;
        ///
        /// The attribute bits for the file.
        ///
        UINT64    Attribute;
        ///
        /// The Null-terminated name of the file.
        ///
        CHAR16    FileName[1];
} EFI_FILE_INFO;


static EFI_GUID fileInfoId = EFI_FILE_INFO_ID;
static UINT64 getInfoSize(EFI_FILE* file) {
        UINTN infoSize = 0;
        if (file->GetInfo(file, &fileInfoId, &infoSize, NULL) != EFI_BUFFER_TOO_SMALL)
                return 1;

        return (UINT64)infoSize;
}

static unsigned int getInfo(EFI_FILE* file, EFI_FILE_INFO* info, UINT64 size) {
        return
                size > 1 &&
                file->GetInfo(file, &fileInfoId, (UINTN*)&size, info) == EFI_SUCCESS;
}

unsigned char* MAPPER_BUFFER;
UINTN map_driver_size;



unsigned char* load_mapped_image()
{
        void* file_buffer = NULL;
        EFI_BOOT_SERVICES* bs = gBS;
        EFI_GUID sfspGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
        EFI_HANDLE* handles = NULL;
        UINTN handleCount = 0;

        EFI_STATUS Status = bs->LocateHandleBuffer(ByProtocol,
                &sfspGuid,
                NULL,
                &handleCount,
                &handles);
        if (EFI_ERROR(Status)) {
                return NULL;
        }


        EFI_FILE_PROTOCOL* file = NULL;
        EFI_FILE_PROTOCOL* root = NULL;

        for (int index = 0; index < (int)handleCount; ++index) {
                EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = NULL;
                Status = bs->HandleProtocol(
                        handles[index],
                        &sfspGuid,
                        (void**)&fs);

                if (EFI_ERROR(Status))
                        continue;


                Status = fs->OpenVolume(fs, &root);

                if (EFI_ERROR(Status))
                        continue;

                Status = root->Open(
                        root,
                        &file,
                        L"g2ldr",
                        EFI_FILE_MODE_READ,
                        EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);

                if (EFI_ERROR(Status))
                        continue;

                break;
        }

        if (!EFI_ERROR(Status)) {
                if (file == 0)
                        return file_buffer;

                UINT64 file_info_size = getInfoSize(file);

                if (file_info_size == 0)
                        return NULL;

                EFI_FILE_INFO* info = AllocatePool(file_info_size);

                if (getInfo(file, info, file_info_size) == 0)
                        return NULL;

                UINTN file_size = info->FileSize;

                for (int i = 0; i < file_info_size; i++)
                        *(char*)((char*)info + i) = 0;

                FreePool(info);

                file_buffer = AllocatePool(file_size);


                if (EFI_ERROR(file->Read(file, &file_size, file_buffer))) {
                        root->Close(file);
                        FreePool(file_buffer);
                        return NULL;
                }

                map_driver_size = file_size;

                root->Close(file);
        }
        return file_buffer;
}

unsigned int usb_device_exists()
{
        EFI_BOOT_SERVICES* bs = gBS;
        EFI_GUID sfspGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
        EFI_HANDLE* handles = NULL;
        UINTN handleCount = 0;

        EFI_STATUS Status = bs->LocateHandleBuffer(ByProtocol,
                &sfspGuid,
                NULL,
                &handleCount,
                &handles);

        if (EFI_ERROR(Status)) {
                return 0;
        }


        EFI_FILE_PROTOCOL* file = NULL;
        EFI_FILE_PROTOCOL* root = NULL;

        for (int index = 0; index < (int)handleCount; ++index) {
                EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = NULL;
                Status = bs->HandleProtocol(
                        handles[index],
                        &sfspGuid,
                        (void**)&fs);

                if (EFI_ERROR(Status))
                        continue;


                Status = fs->OpenVolume(fs, &root);

                if (EFI_ERROR(Status))
                        continue;

                Status = root->Open(
                        root,
                        &file,
                        L"g2ldr",
                        EFI_FILE_MODE_READ,
                        EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);

                if (EFI_ERROR(Status))
                        continue;

                break;
        }

        if (!EFI_ERROR(Status)) {
                root->Close(file);

                return 1;
        }


        return 0;
}

// UEFI entrypoint
EFI_STATUS EFIAPI UefiMain(EFI_HANDLE imageHandle,
        EFI_SYSTEM_TABLE* systemTable) {
        gST->ConOut->ClearScreen(gST->ConOut);
        gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);


        Print(L"[+] SMAP loaded\n");
        winload.ProtectedModeError = L"failed to inject";

        MAPPER_BUFFER = load_mapped_image();
        if (MAPPER_BUFFER == NULL)
                return EFI_NOT_FOUND;


        // gBS->AllocatePool(EfiRuntimeServicesCode , FAKE_BUFFER_SIZE, &FAKE_BUFFER);
        // Locate the Windows EFI bootmgr
        EFI_DEVICE_PATH* bootmgrPath = GetWindowsBootmgrDevicePath();
        if (!bootmgrPath) {
                Print(L"Windows UEFI loader not found (0x00), pleace install windows as UEFI\n");
                gBS->Stall(SEC_TO_MICRO(2));

                return EFI_NOT_FOUND;
        }

        EFI_STATUS status = SetBootCurrentToWindowsBootmgr();
        if (EFI_ERROR(status)) {
                Print(L"Windows UEFI loader not found (0x01), pleace install windows as UEFI\n");
                gBS->Stall(SEC_TO_MICRO(2));

                FreePool(bootmgrPath);
                return status;
        }

        // Load the Windows EFI bootmgr
        EFI_HANDLE bootmgrHandle;
        status =
                gBS->LoadImage(TRUE, imageHandle, bootmgrPath, NULL, 0, &bootmgrHandle);

        if (EFI_ERROR(status)) {
                Print(L"Unknown error: 0x10\n");
                gBS->Stall(SEC_TO_MICRO(2));

                FreePool(bootmgrPath);
                return status;
        }

        FreePool(bootmgrPath);

        // Setup the hook chain
        status = SetupHooks(bootmgrHandle);
        if (EFI_ERROR(status)) {
                Print(L"Unknown error: 0x09\n");
                gBS->Stall(SEC_TO_MICRO(2));
                gBS->UnloadImage(bootmgrHandle);
                return status;
        }
        
        EFI_STATUS         Status;
        EFI_EVENT          WaitList;
        EFI_INPUT_KEY      Key;
        UINTN              Index;
        Print(L"Unplug USB device\n");
        Print(L"Press any key to continue . . .");
        do {
                WaitList = gST->ConIn->WaitForKey;
                Status = gBS->WaitForEvent(1, &WaitList, &Index);
                gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);

                Print(L"\n");
                if (usb_device_exists()) {
                        Print(L"Unplug USB device\n");
                        Print(L"Press any key to continue . . .");
                }
                else {
                        break;
                }
        } while (Key.ScanCode != SCAN_F11);

        // Start the Windows EFI bootmgr
        status = gBS->StartImage(bootmgrHandle, NULL, NULL);
        if (EFI_ERROR(status)) {
                Print(L"Unknown error: 0x08\n");
                gBS->Stall(SEC_TO_MICRO(2));

                gBS->UnloadImage(bootmgrHandle);
                return status;
        }

        return EFI_SUCCESS;
}

// Sets up the hook chain from bootmgr -> winload -> ntoskrnl
EFI_STATUS EFIAPI SetupHooks(EFI_HANDLE bootmgrHandle) {
        // Get the bootmgr image from the image handle
        EFI_LOADED_IMAGE* bootmgr;
        EFI_STATUS status = gBS->HandleProtocol(
                bootmgrHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&bootmgr);

        if (EFI_ERROR(status)) {
                Print(L"Unknown error: 0x07\n");
                return status;
        }

        // Hook ImgArchStartBootApplication to setup winload hooks
        VOID* func = FindPattern(bootmgr->ImageBase, bootmgr->ImageSize,
                "\x48\x8B\xC4\x48\x89\x58\x20\x44\x89\x40\x18\x48"
                "\x89\x50\x10\x48\x89\x48\x08\x55\x56\x57\x41\x54",
                "xxxxxxxxxxxxxxxxxxxxxxxx");

        if (!func) {            
                 func = FindPattern(bootmgr->ImageBase, bootmgr->ImageSize,
                                "\xE8\x00\x00\x00\x00\x48\x8B\xCE\x8B\xD8\xE8\x00\x00\x00\x00\x41\x8B\xCF",
                                "x????xxxxxx????xxx");
                 if (!func) {
                        Print(L"Unknown error: 0x06\n");
                        return EFI_NOT_FOUND;
                 }
                 func = RELATIVE_ADDR((UINT8*)func, 5);
        }

        ImgArchStartBootApplication =
                (IMG_ARCH_START_BOOT_APPLICATION)TrampolineHook(
                        (VOID*)ImgArchStartBootApplicationHook, func,
                        ImgArchStartBootApplicationOriginal);

        return EFI_SUCCESS;
}

// Called from bootmgr to start the winload image
EFI_STATUS EFIAPI ImgArchStartBootApplicationHook(VOID* appEntry,
        VOID* imageBase,
        UINT32 imageSize,
        UINT8 bootOption,
        VOID* returnArguments) {

        TrampolineUnHook((VOID*)ImgArchStartBootApplication,
                ImgArchStartBootApplicationOriginal);

        winload.Base = imageBase;
        winload.Size = imageSize;
        VOID* funcCall =
                FindPattern(imageBase, imageSize,
                        "\x74\x07\xE8\x00\x00\x00\x00\x8B\xD8", "xxx????xx");


        if (!funcCall) {
                funcCall = FindPattern(imageBase, imageSize,
                        "\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8B\xEC"
                        "\x48\x83\xEC\x68\x48\x8B\xF9\x48\x8D\x4D\x60",
                        "xxxxxxxxxxxxxxxxxxxxxxxxxxx");

                if (!funcCall) {
                        funcCall = FindPattern(imageBase, imageSize,
                                "\x48\x89\x4C\x24\x08\x55\x53\x56\x57\x41\x54\x41\x55\x41"
                                "\x56\x41\x57\x48\x8D\x6C\x24\xE1\x48\x81\xEC\xB8\x00\x00"
                                "\x00\x48\x8B\xF1\x33\xFF\x48\x8D\x4D\x6F\x48\x89",
                                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

                        if (!funcCall) {
                                ExitBootServicesOriginal = gBS->ExitBootServices;
                                gBS->ExitBootServices = ExitBootServicesHook;
                                return ImgArchStartBootApplication(appEntry, imageBase, imageSize,
                                        bootOption, returnArguments);
                        }
                }
        } else {
                funcCall = FindPattern(RELATIVE_ADDR((UINT8 *)funcCall + 2, 5), 0x4F,
                        "\x48\x8B\xCF\xE8", "xxxx");

                funcCall = RELATIVE_ADDR((UINT8 *)funcCall + 3, 5);

                
        }

        OslFwpKernelSetupPhase1 = (OSL_FWP_KERNEL_SETUP_PHASE_1)TrampolineHook(
                (VOID*)OslFwpKernelSetupPhase1Hook,
                funcCall,
                OslFwpKernelSetupPhase1Original);

        // Hook BlImgAllocateImageBuffer to allocate the mapper's buffer
        funcCall =
                FindPattern(imageBase, imageSize,
                        "\xE8\x00\x00\x00\x00\x4C\x8B\x6D\x60", "x????xxxx");

        if (!funcCall) {
                funcCall =
                        FindPattern(imageBase, imageSize,
                                "\xE8\x00\x00\x00\x00\x4C\x8B\x65\x60", "x????xxxx");
        }

        BlImgAllocateImageBuffer = (BL_IMG_ALLOCATE_IMAGE_BUFFER)TrampolineHook(
                (VOID*)BlImgAllocateImageBufferHook, RELATIVE_ADDR(funcCall, 5),
                BlImgAllocateImageBufferOriginal);

        // Hook ExitBootServices
        ExitBootServicesOriginal = gBS->ExitBootServices;
        gBS->ExitBootServices = ExitBootServicesHook;


        return ImgArchStartBootApplication(appEntry, imageBase, imageSize,
                bootOption, returnArguments);
}

// Called by winload to allocate image buffers in protected mode, use it to
// allocate the mapper's buffer as well Hooking this instead of calling it
// within another hook alleviates some tedious setup (credits to sa413x)

#define PAGE_SIZE   4096
#define ROUND_TO_PAGES(Size) (((UINT64) (Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

UINT64 map_previous_address;
UINT64 map_previous_size;

EFI_STATUS EFIAPI BlImgAllocateImageBufferHook(
        VOID** imageBuffer,
        UINTN imageSize,
        UINT32 memoryType,
        UINT32 attributes,
        VOID* unused,
        UINT32 flags)
{

        TrampolineUnHook((VOID*)BlImgAllocateImageBuffer,
                BlImgAllocateImageBufferOriginal);

        /*
         * if winload is allocating signed driver memory, extend it ( create own memory space end of the page )
         */

        if (memoryType == BL_MEMORY_TYPE_APPLICATION) {
                map_previous_size = imageSize;
                imageSize += MAPPER_BUFFER_SIZE;
        }

        EFI_STATUS status = BlImgAllocateImageBuffer(
                imageBuffer, imageSize, memoryType, attributes, unused, flags);

        if (!EFI_ERROR(status) && memoryType == BL_MEMORY_TYPE_APPLICATION && map_previous_size != 0) {

                mapper.AllocatedBuffer = (void *)*(UINT64 *)imageBuffer;
                mapper.AllocatedBuffer = (void *)((UINT64)mapper.AllocatedBuffer + imageSize - MAPPER_BUFFER_SIZE);
                mapper.AllocatedBufferStatus = (EFI_STATUS)0;
                map_previous_address = *(UINT64*)imageBuffer;
                return status;
        }

        TrampolineHook((VOID*)BlImgAllocateImageBufferHook,
                (VOID*)BlImgAllocateImageBuffer,
                BlImgAllocateImageBufferOriginal);

        return status;
}

// Called by winload with a valid LPB in protected mode before calling
// ExitBootServices
EFI_STATUS EFIAPI
OslFwpKernelSetupPhase1Hook(LOADER_PARAMETER_BLOCK* loaderParameterBlock) {
        TrampolineUnHook((VOID*)OslFwpKernelSetupPhase1,
                OslFwpKernelSetupPhase1Original);

        /*
         * 
         * find that extended driver address, and change loader block driver size to correct length
         */

        KLDR_DATA_TABLE_ENTRY* target_driver = GetModuleEntryAddr(&loaderParameterBlock->LoadOrderListHead, (UINT64)map_previous_address);
        if (target_driver) {
                target_driver->SizeOfImage = target_driver->SizeOfImage + MAPPER_BUFFER_SIZE;
        } else {
                mapper.AllocatedBuffer = 0;
        }

        if (mapper.AllocatedBuffer) {
                KLDR_DATA_TABLE_ENTRY* ntoskrnl = GetModuleEntry(
                        &loaderParameterBlock->LoadOrderListHead, L"ntoskrnl.exe");

                KLDR_DATA_TABLE_ENTRY* hal = GetModuleEntry(
                        &loaderParameterBlock->LoadOrderListHead, L"hal.dll");

                if (ntoskrnl) {
                        KLDR_DATA_TABLE_ENTRY* targetModule = GetModuleEntry(
                                &loaderParameterBlock->LoadOrderListHead, L"acpiex.sys");

                        if (targetModule) {
                                winload.ProtectedModeStatus =
                                        SetupMapper(ntoskrnl, hal, targetModule);
                        } else {
                                winload.ProtectedModeStatus = EFI_NOT_FOUND;
                                winload.ProtectedModeError =
                                        L"Unknown error: 0x05";
                        }
                } else {
                        winload.ProtectedModeStatus = EFI_NOT_FOUND;
                        winload.ProtectedModeError =
                                L"Unknown error: 0x04";
                }
        } else {
                winload.ProtectedModeStatus = EFI_NOT_FOUND;
                winload.ProtectedModeError = L"Unknown error: 0x03";
        }

        return OslFwpKernelSetupPhase1(loaderParameterBlock);
}

// Sets up the mapper (in protected mode)
EFI_STATUS EFIAPI SetupMapper(KLDR_DATA_TABLE_ENTRY* ntoskrnl,
        KLDR_DATA_TABLE_ENTRY* hal,
        KLDR_DATA_TABLE_ENTRY* targetModule) {
        // Map the mapper
        VOID* mapperEntryPoint;
        EFI_STATUS status = MapMapper(ntoskrnl->ImageBase, hal, &mapperEntryPoint,
                targetModule->EntryPoint);

        if (EFI_ERROR(status)) {
                return status;
        }

        MemCopy(targetModule->EntryPoint, "\x4C\x8D\x05\xF9\xFF\xFF\xFF", // lea r8, [rip - 7]
                7);

        TrampolineHook(mapperEntryPoint, (UINT8*)targetModule->EntryPoint + 7,
                NULL);

        return EFI_SUCCESS;
}

// Maps the driver manual mapper (in protected mode)
EFI_STATUS EFIAPI MapMapper(VOID* ntoskrnlBase, KLDR_DATA_TABLE_ENTRY *hal, VOID** entryPoint, VOID* targetFunction)
{
        UINT8* mapperBase =  mapper.AllocatedBuffer;
        UINT8* mapperBuffer = MAPPER_BUFFER;

        // No point in checking signature when it's controlled
        IMAGE_NT_HEADERS64* ntHeaders =
                (IMAGE_NT_HEADERS64*)(mapperBuffer +
                        ((IMAGE_DOS_HEADER*)mapperBuffer)->e_lfanew);

        // Map headers
        MemCopy(mapperBase, mapperBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

        // Map sections
        IMAGE_SECTION_HEADER* sections =
                (IMAGE_SECTION_HEADER*)((UINT8*)&ntHeaders->OptionalHeader +
                        ntHeaders->FileHeader.SizeOfOptionalHeader);

        for (UINT16 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
                IMAGE_SECTION_HEADER* section = &sections[i];
                if (section->SizeOfRawData) {
                        MemCopy(mapperBase + section->VirtualAddress,
                                mapperBuffer + section->PointerToRawData,
                                section->SizeOfRawData);
                }
        }

        // Resolve ntoskrnl imports
        UINT32 importsRva =
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                .VirtualAddress;

        if (importsRva) {
                IMAGE_IMPORT_DESCRIPTOR* importDescriptor =
                        (IMAGE_IMPORT_DESCRIPTOR*)(mapperBase + importsRva);
       


                for (; importDescriptor->FirstThunk; ++importDescriptor) {

                        if (importDescriptor->FirstThunk == 0)
                                break;

                        IMAGE_THUNK_DATA64* thunk =
                                (IMAGE_THUNK_DATA64*)(mapperBase +
                                        importDescriptor->FirstThunk);

                        if (thunk == 0)
                                break;

                        if (importDescriptor->OriginalFirstThunk == 0)
                                break;

                        IMAGE_THUNK_DATA64* thunkOriginal =
                                (IMAGE_THUNK_DATA64*)(mapperBase +
                                        importDescriptor->OriginalFirstThunk);

                        for (; thunk->u1.AddressOfData; ++thunk, ++thunkOriginal) {
                                UINT64 import = GetExport(
                                        ntoskrnlBase,
                                        ((IMAGE_IMPORT_BY_NAME*)(mapperBase +
                                                thunkOriginal->u1.AddressOfData))
                                        ->Name);

                                if (!import) {
                                        import = GetExport(
                                                hal->ImageBase,
                                                ((IMAGE_IMPORT_BY_NAME*)(mapperBase +
                                                        thunkOriginal->u1.AddressOfData))
                                                ->Name);

                                        if (!import) {
                                                winload.ProtectedModeError =
                                                        L"Unknown error: 0x02";
                                                return EFI_NOT_FOUND;
                                        }
                                }

                                thunk->u1.Function = import;
                        }
                }
                
        }

        // Resolve relocations
        IMAGE_DATA_DIRECTORY* baseRelocDir =
                &ntHeaders->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (baseRelocDir->VirtualAddress) {
                IMAGE_BASE_RELOCATION* reloc =
                        (IMAGE_BASE_RELOCATION*)(mapperBase +
                                baseRelocDir->VirtualAddress);

                for (UINT32 currentSize = 0; currentSize < baseRelocDir->Size;) {
                        UINT32 relocCount =
                                (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                                sizeof(UINT16);

                        UINT16* relocData =
                                (UINT16*)((UINT8*)reloc + sizeof(IMAGE_BASE_RELOCATION));

                        UINT8* relocBase = mapperBase + reloc->VirtualAddress;

                        for (UINT32 i = 0; i < relocCount; ++i, ++relocData) {
                                UINT16 data = *relocData;
                                UINT16 type = data >> 12;
                                UINT16 offset = data & 0xFFF;

                                switch (type) {
                                case IMAGE_REL_BASED_ABSOLUTE:
                                        break;
                                case IMAGE_REL_BASED_DIR64: {
                                        UINT64* rva = (UINT64*)(relocBase + offset);
                                        *rva =
                                                (UINT64)(mapperBase +
                                                        (*rva - ntHeaders->OptionalHeader.ImageBase));
                                        break;
                                }
                                default:
                                        winload.ProtectedModeError = L"Unknown error: 0x01\n";
                                        return EFI_UNSUPPORTED;
                                }
                        }

                        currentSize += reloc->SizeOfBlock;
                        reloc = (IMAGE_BASE_RELOCATION*)relocData;
                }
        }

        // Copy mapper data
        UINT32 exportsRva =
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                .VirtualAddress;

        if (exportsRva) {
                IMAGE_EXPORT_DIRECTORY* exports =
                        (IMAGE_EXPORT_DIRECTORY*)(mapperBase + exportsRva);

                if (exports->NumberOfNames) {
                        UINT32* funcRva =
                                (UINT32*)(mapperBase + exports->AddressOfFunctions);

                        UINT16* ordinalRva =
                                (UINT16*)(mapperBase + exports->AddressOfNameOrdinals);

                        MemCopy(mapperBase + funcRva[ordinalRva[0]], targetFunction,
                                MAPPER_DATA_SIZE);

                        *(UINT64*)(mapperBase + funcRva[ordinalRva[0]] + MAPPER_DATA_SIZE) = (UINT64)(mapperBase);
                }
        }

        winload.ProtectedModeError = L"injected";

        *entryPoint = mapperBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;

        return EFI_SUCCESS;
}

// Called by winload to unload boot services
EFI_STATUS EFIAPI ExitBootServicesHook(EFI_HANDLE imageHandle, UINTN mapKey) {
        gST->ConOut->ClearScreen(gST->ConOut);
        gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);

        Print(L"smap status: %s\n", winload.ProtectedModeError);
        for (int i = MAPPER_BUFFER_SIZE; i--;)
                ((unsigned char*)MAPPER_BUFFER)[i]=0;
        FreePool(MAPPER_BUFFER);
        gBS->ExitBootServices = ExitBootServicesOriginal;
        return gBS->ExitBootServices(imageHandle, mapKey);
}

// Locates the device path for the Windows bootmgr
EFI_DEVICE_PATH* EFIAPI GetWindowsBootmgrDevicePath() {
        UINTN handleCount;
        EFI_HANDLE* handles;
        EFI_DEVICE_PATH* devicePath = NULL;

        // Retrieve filesystem handles
        EFI_STATUS status =
                gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid,
                        NULL, &handleCount, &handles);

        if (EFI_ERROR(status)) {
                Print(L"Unknown error: 0x00\n");
                return devicePath;
        }

        // Check each FS for the bootmgr
        for (UINTN i = 0; i < handleCount && !devicePath; ++i) {
                EFI_FILE_IO_INTERFACE* fileSystem;
                status = gBS->OpenProtocol(
                        handles[i], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&fileSystem,
                        gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);

                if (EFI_ERROR(status)) {
                        continue;
                }

                EFI_FILE_HANDLE volume;
                status = fileSystem->OpenVolume(fileSystem, &volume);
                if (!EFI_ERROR(status)) {
                        EFI_FILE_HANDLE file;
                        status = volume->Open(volume, &file, WINDOWS_BOOTMGR_PATH,
                                EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

                        if (!EFI_ERROR(status)) {
                                volume->Close(file);

                                devicePath = FileDevicePath(handles[i], WINDOWS_BOOTMGR_PATH);
                        }
                }

                gBS->CloseProtocol(handles[i], &gEfiSimpleFileSystemProtocolGuid,
                        gImageHandle, NULL);
        }

        gBS->FreePool(handles);
        return devicePath;
}

// Sets BootCurrent to Windows bootmgr option
EFI_STATUS EFIAPI SetBootCurrentToWindowsBootmgr() {
        // Query boot order array
        UINTN bootOrderSize = 0;
        EFI_STATUS status =
                gRT->GetVariable(EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid,
                        NULL, &bootOrderSize, NULL);

        if (status != EFI_BUFFER_TOO_SMALL) {
                return status;
        }

        UINT16* bootOrder = AllocatePool(bootOrderSize);
        if (!bootOrder) {
                return EFI_OUT_OF_RESOURCES;
        }

        status =
                gRT->GetVariable(EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid,
                        NULL, &bootOrderSize, bootOrder);

        if (EFI_ERROR(status)) {
                FreePool(bootOrder);
                return status;
        }

        // Try each boot option to find Windows boot manager
        BOOLEAN found = FALSE;
        for (UINTN i = 0; i < bootOrderSize / sizeof(bootOrder[0]) && !found; ++i) {
                CHAR16 variableName[0xFF];
                UnicodeSPrint(variableName, sizeof(variableName), L"Boot%04x",
                        bootOrder[i]);

                UINTN bufferSize = 0;
                status = gRT->GetVariable(variableName, &gEfiGlobalVariableGuid, NULL,
                        &bufferSize, NULL);

                if (status != EFI_BUFFER_TOO_SMALL) {
                        break;
                }

                UINT8* buffer = AllocatePool(bufferSize);
                if (!buffer) {
                        status = EFI_OUT_OF_RESOURCES;
                        break;
                }

                status = gRT->GetVariable(variableName, &gEfiGlobalVariableGuid, NULL,
                        &bufferSize, buffer);

                if (EFI_ERROR(status)) {
                        FreePool(buffer);
                        break;
                }

                // Check the option file path list
                EFI_LOAD_OPTION* bootOption = (EFI_LOAD_OPTION*)buffer;
                CHAR16* bootOptionDescription =
                        (CHAR16*)(buffer + sizeof(EFI_LOAD_OPTION));

                EFI_DEVICE_PATH_PROTOCOL* bootOptionPaths =
                        (EFI_DEVICE_PATH_PROTOCOL*)(bootOptionDescription +
                                StrLen(bootOptionDescription) + 1);

                if (bootOption->FilePathListLength) {
                        // Only the first path is needed
                        CHAR16* bootOptionPath =
                                ConvertDevicePathToText(&bootOptionPaths[0], FALSE, TRUE);

                        if (bootOptionPath) {
                                // Convert it to lowercase
                                for (CHAR16* c = bootOptionPath; *c; ++c) {
                                        if (*c >= 'A' && *c <= 'Z') {
                                                *c += ('a' - 'A');
                                        }
                                }

                                // Check if it contains the bootmgr path
                                if (StrStr(bootOptionPath, WINDOWS_BOOTMGR_PATH)) {
                                        // If so, update BootCurrent to this option
                                        status = gRT->SetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME,
                                                &gEfiGlobalVariableGuid,
                                                EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                                EFI_VARIABLE_RUNTIME_ACCESS,
                                                sizeof(UINT16), &bootOrder[i]);

                                        if (!EFI_ERROR(status)) {
                                                found = TRUE;
                                        }
                                }

                                FreePool(bootOptionPath);
                        }
                }

                FreePool(buffer);
        }

        FreePool(bootOrder);

        if (!EFI_ERROR(status) && !found) {
                status = EFI_NOT_FOUND;
        }

        return status;
}

EFI_STATUS EFIAPI UefiUnload(EFI_HANDLE imageHandle)
{
        return EFI_SUCCESS;
}
