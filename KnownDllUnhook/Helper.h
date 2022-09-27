#pragma once

#include <Windows.h>


#define PRINT( STR, ... )                                                                   \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  



#define NtAllocateVirtualMemory_StrHashed       0x014044AE
#define NtProtectVirtualMemory_StrHashed        0xE67C7320
#define NtCreateSection_StrHashed               0xAC2EDA02
#define NtOpenSection_StrHashed                 0xD443EC8C
#define NtMapViewOfSection_StrHashed            0x92DD00B3
#define NtUnmapViewOfSection_StrHashed          0x12D71086
#define NtClose_StrHashed                       0x7B3F64A4




PVOID _memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length);

void _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);

wchar_t* _strcpy(wchar_t* dest, const wchar_t* src);

wchar_t* _strcat(wchar_t* dest, const wchar_t* src);



