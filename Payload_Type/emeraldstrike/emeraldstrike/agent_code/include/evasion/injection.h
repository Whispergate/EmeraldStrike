#ifndef EMERALDSTRIKE_INJECTION_H
#define EMERALDSTRIKE_INJECTION_H

#include "../config.h"
#include "../common.h"

HANDLE inject_shellcode_into(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step);
BOOL inject_shellcode(PINSTANCE inst, DWORD pid, BYTE* shellcode, DWORD sc_len, DWORD* step);

#endif // EMERALDSTRIKE_INJECTION_H
