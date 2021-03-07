#ifndef CRC32_H
#define CRC32_H

#ifdef _KERNEL_MODE

typedef unsigned __int8  BYTE;
typedef unsigned __int16 WORD;
typedef unsigned __int32 DWORD;
typedef unsigned __int64 QWORD;
typedef int BOOL;

#endif

DWORD crc32(PCSTR buf, DWORD len, DWORD init);

extern DWORD g_encryption_key;

#endif
