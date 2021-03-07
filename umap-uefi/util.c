#include "stdafx.h"

VOID MemCopy(VOID* dest, VOID* src, UINTN size) {
        for (UINT8* d = dest, *s = src; size--; *d++ = *s++)
                ;
}

BOOLEAN CheckMask(unsigned char* base, unsigned char* pattern, unsigned char* mask) {
        for (; *mask; ++base, ++pattern, ++mask) {
                if (*mask == 'x' && *base != *pattern) {
                        return FALSE;
                }
        }

        return TRUE;
}

VOID* FindPattern(unsigned char* base, UINTN size, unsigned char* pattern, unsigned char* mask) {
        size -= AsciiStrLen(mask);

        for (UINTN i = 0; i <= size; ++i) {
                VOID* addr = &base[i];
                if (CheckMask(addr, pattern, mask)) {
                        return addr;
                }
        }

        return NULL;
}

VOID* TrampolineHook(VOID* dest, VOID* src, UINT8 original[JMP_SIZE]) {
        if (original) {
                MemCopy(original, src, JMP_SIZE);
        }

        
        MemCopy(src, "\xFF\x25\x00\x00\x00\x00", 6);
        *(VOID**)((UINT8*)src + 6) = dest;
        

        /*
        MemCopy(src, "\x48\xB8", 2);
        *(VOID**)((UINT8*)src + 2) = dest;
        MemCopy(((char *)src + 10), "\xFF\xE0", 2);
        */


        return src;
}

VOID TrampolineUnHook(VOID* src, UINT8 original[JMP_SIZE]) {
        MemCopy(src, original, JMP_SIZE);
}


INTN
EFIAPI
StrnCmpA (
  IN      CONST CHAR16              *FirstString,
  IN      CONST CHAR16              *SecondString,
  IN      UINTN                     Length
  )
{
        while ((*FirstString != L'\0') &&
                (*SecondString != L'\0') &&
                (AsciiCharToUpper((CHAR8)*FirstString) == AsciiCharToUpper((CHAR8)*SecondString)) &&
                (Length > 1)) {
                FirstString++;
                SecondString++;
                Length--;
        }
        return *FirstString - *SecondString;
}

KLDR_DATA_TABLE_ENTRY* GetModuleEntry(LIST_ENTRY* entry, CHAR16* name)
{
        LIST_ENTRY *list = entry;
        while ((list = list->ForwardLink) != entry) {
                KLDR_DATA_TABLE_ENTRY *module =
                        CONTAINING_RECORD(list, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (module && StrnCmpA(name, module->BaseImageName.Buffer,
                        module->BaseImageName.Length) == 0) {
                        
                        return module;
                }
        }
        return NULL;
}

KLDR_DATA_TABLE_ENTRY* GetModuleEntryAddr(LIST_ENTRY* entry, UINT64 base)
{
        LIST_ENTRY *list = entry;
        while ((list = list->ForwardLink) != entry) {
                KLDR_DATA_TABLE_ENTRY *module =
                        CONTAINING_RECORD(list, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                
                if (module && (UINT64)module->ImageBase == base) {
                        
                        return module;
                }
        }
        return NULL;
}

KLDR_DATA_TABLE_ENTRY* GetModuleEntry2(LIST_ENTRY* entry, CHAR8* name)
{
        LIST_ENTRY *list = entry;
        while ((list = list->ForwardLink) != entry) {
                KLDR_DATA_TABLE_ENTRY *module =
                        CONTAINING_RECORD(list, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (module && GetExport(module->ImageBase, name))
                {
                        return module;
                }
        }

        return NULL;
}

UINT64 GetExport(UINT8* base, CHAR8* export) {
        IMAGE_DOS_HEADER* dosHeaders = (IMAGE_DOS_HEADER*)base;
        if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
                return 0;
        }

        IMAGE_NT_HEADERS64* ntHeaders =
                (IMAGE_NT_HEADERS64*)(base + dosHeaders->e_lfanew);

        UINT32 exportsRva =
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                .VirtualAddress;

        if (!exportsRva) {
                return 0;
        }

        IMAGE_EXPORT_DIRECTORY* exports =
                (IMAGE_EXPORT_DIRECTORY*)(base + exportsRva);

        UINT32* nameRva = (UINT32*)(base + exports->AddressOfNames);

        for (UINT32 i = 0; i < exports->NumberOfNames; ++i) {
                CHAR8* func = (CHAR8*)(base + nameRva[i]);

                if (AsciiStrCmp(func, export) == 0) {
                        UINT32* funcRva = (UINT32*)(base + exports->AddressOfFunctions);
                        UINT16* ordinalRva =
                                (UINT16*)(base + exports->AddressOfNameOrdinals);

                        return (UINT64)base + funcRva[ordinalRva[i]];
                }
        }

        return 0;
}
