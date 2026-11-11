#include "config.h"
#ifdef INCLUDE_CMD_STAT

#include "commands.h"
#include "json_out.h"

typedef DWORD (WINAPI *fn_GetFileAttributesExA_t)(LPCSTR, DWORD, void*);

// WIN32_FILE_ATTRIBUTE_DATA layout
// DWORD attrs; FILETIME ctime, atime, wtime; DWORD size_hi, size_lo;
#define WFAD_ATTRS  0
#define WFAD_CTIME  4
#define WFAD_ATIME  12
#define WFAD_WTIME  20
#define WFAD_SIZEHI 28
#define WFAD_SIZELO 32
#define WFAD_SIZE   36

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

static void filetime_to_iso(DWORD ft_lo, DWORD ft_hi, char* out, int outsz) {
    unsigned __int64 ft = ((unsigned __int64)ft_hi << 32) | ft_lo;
    // FILETIME -> Unix epoch: subtract 116444736000000000 (100ns intervals)
    unsigned __int64 since1601 = ft - 116444736000000000ULL;
    DWORD unix_time = (DWORD)es_u64_div(since1601, 10000000U, NULL);
    DWORD days = unix_time / 86400;
    DWORD secs = unix_time % 86400;
    DWORD hour = secs / 3600;
    DWORD min  = (secs % 3600) / 60;
    DWORD sec  = secs % 60;

    // civil-from-days (Howard Hinnant's algorithm), 32-bit safe
    DWORD z = days + 719468;
    DWORD era = z / 146097;
    DWORD doe = z - era * 146097;                     // [0, 146096]
    DWORD yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365; // [0, 399]
    DWORD y   = yoe + era * 400;
    DWORD doy = doe - (365*yoe + yoe/4 - yoe/100);    // [0, 365]
    DWORD mp  = (5*doy + 2)/153;                      // [0, 11]
    DWORD d   = doy - (153*mp+2)/5 + 1;               // [1, 31]
    DWORD m   = (mp < 10) ? (mp + 3) : (mp - 9);      // [1, 12]
    if (m <= 2) y += 1;

    int p = 0;
    out[p++] = '0' + (char)(y / 1000); y %= 1000;
    out[p++] = '0' + (char)(y / 100);  y %= 100;
    out[p++] = '0' + (char)(y / 10);
    out[p++] = '0' + (char)(y % 10);
    out[p++] = '-';
    out[p++] = '0' + (char)(m / 10);
    out[p++] = '0' + (char)(m % 10);
    out[p++] = '-';
    out[p++] = '0' + (char)(d / 10);
    out[p++] = '0' + (char)(d % 10);
    out[p++] = 'T';
    out[p++] = '0' + (char)(hour / 10);
    out[p++] = '0' + (char)(hour % 10);
    out[p++] = ':';
    out[p++] = '0' + (char)(min / 10);
    out[p++] = '0' + (char)(min % 10);
    out[p++] = ':';
    out[p++] = '0' + (char)(sec / 10);
    out[p++] = '0' + (char)(sec % 10);
    out[p++] = 'Z';
    out[p] = 0;
    (void)outsz;
}

VOID cmd_stat(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD path_len = 0;
    char* parg = parser_string(args, &path_len);
    char path[300] = {0};
    if (parg && path_len) {
        for (DWORD k = 0; k < path_len && k < sizeof(path) - 1; k++) path[k] = parg[k];
    }
    if (!path[0]) {
        package_add_string(inst, response, XSTR("usage: stat <path>"));
        response->is_error = TRUE;
        return;
    }

    xstr(_k32, "kernel32.dll");
    HMODULE h_k32 = inst->Win32.LoadLibraryA(_k32);
    fn_GetFileAttributesExA_t pGFA = h_k32 ?
        (fn_GetFileAttributesExA_t)(void*)inst->Win32.GetProcAddress(h_k32, "GetFileAttributesExA") : NULL;
    if (!pGFA) {
        package_add_string(inst, response, XSTR("resolve failed"));
        response->is_error = TRUE;
        return;
    }

    BYTE wfad[WFAD_SIZE] = {0};
    if (!pGFA(path, 0 /*GetFileExInfoStandard*/, wfad) || wfad[WFAD_ATTRS] == 0xFFFFFFFF) {
        JSON_BUF jb;
        j_init(&jb);
        j_append_raw(&jb, "{\"path\":");
        j_append_str(&jb, path);
        j_append_raw(&jb, ",\"exists\":false}");
        package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
        return;
    }

    unsigned __int64 size = ((unsigned __int64)*(DWORD*)(wfad + WFAD_SIZEHI) << 32)
                          | *(DWORD*)(wfad + WFAD_SIZELO);

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"path\":");
    j_append_str(&jb, path);
    j_append_raw(&jb, ",\"exists\":true,\"size\":");
    j_append_u64(&jb, size);
    j_append_raw(&jb, ",\"attributes\":");
    j_append_uint(&jb, *(DWORD*)(wfad + WFAD_ATTRS));
    j_append_raw(&jb, ",\"created\":\"");
    {
        char iso[32];
        filetime_to_iso(*(DWORD*)(wfad + WFAD_CTIME), *(DWORD*)(wfad + WFAD_CTIME + 4), iso, sizeof(iso));
        j_append_str(&jb, iso);
    }
    j_append_raw(&jb, "\",\"modified\":\"");
    {
        char iso[32];
        filetime_to_iso(*(DWORD*)(wfad + WFAD_WTIME), *(DWORD*)(wfad + WFAD_WTIME + 4), iso, sizeof(iso));
        j_append_str(&jb, iso);
    }
    j_append_raw(&jb, "\",\"accessed\":\"");
    {
        char iso[32];
        filetime_to_iso(*(DWORD*)(wfad + WFAD_ATIME), *(DWORD*)(wfad + WFAD_ATIME + 4), iso, sizeof(iso));
        j_append_str(&jb, iso);
    }
    j_append_raw(&jb, "\"}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
