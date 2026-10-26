#ifndef EMERALDSTRIKE_COFF_H
#define EMERALDSTRIKE_COFF_H

#include "common.h"

#define COFF_MACHINE_AMD64 0x8664
#define COFF_MACHINE_I386  0x14c

#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000

// AMD64 relocation types
#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009

// i386 relocation types
#define IMAGE_REL_I386_DIR32     0x0006
#define IMAGE_REL_I386_DIR32NB   0x0007
#define IMAGE_REL_I386_REL32     0x0014

// COFF symbol storage classes
#define IMAGE_SYM_CLASS_EXTERNAL   2
#define IMAGE_SYM_CLASS_STATIC     3
#define IMAGE_SYM_CLASS_LABEL      6

#pragma pack(push, 1)

typedef struct _COFF_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} COFF_FILE_HEADER, *PCOFF_FILE_HEADER;

typedef struct _COFF_SECTION {
    char  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SECTION, *PCOFF_SECTION;

typedef struct _COFF_RELOCATION {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD  Type;
} COFF_RELOCATION, *PCOFF_RELOCATION;

typedef struct _COFF_SYMBOL {
    union {
        char ShortName[8];
        struct {
            DWORD Zeros;
            DWORD Offset;
        } LongName;
    } Name;
    DWORD Value;
    SHORT SectionNumber;
    WORD  Type;
    BYTE  StorageClass;
    BYTE  NumberOfAuxSymbols;
} COFF_SYMBOL, *PCOFF_SYMBOL;

#pragma pack(pop)

// BOF execution
BOOL bof_execute(PINSTANCE inst, BYTE* coff_data, DWORD coff_size,
                 BYTE* arg_data, DWORD arg_size,
                 char** output, DWORD* output_len);

#endif // EMERALDSTRIKE_COFF_H
