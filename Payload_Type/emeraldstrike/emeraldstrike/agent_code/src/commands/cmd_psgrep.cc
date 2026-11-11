#include "config.h"
#ifdef INCLUDE_CMD_PSGREP

#include "commands.h"
#include "json_out.h"
#include <tlhelp32.h>

VOID cmd_psgrep(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD term_len = 0;
    char* term = parser_string(args, &term_len);
    if (!term || term_len == 0) {
        package_add_string(inst, response, XSTR("Usage: psgrep <name_substring>"));
        response->is_error = TRUE;
        return;
    }

    char lower_term[128];
    for (DWORD i = 0; i < term_len && i < 127; i++)
        lower_term[i] = (term[i] >= 'A' && term[i] <= 'Z') ? term[i] + 32 : term[i];
    lower_term[term_len < 127 ? term_len : 127] = 0;

    HANDLE hSnap = inst->Win32.CreateToolhelp32Snapshot(0x00000002, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        package_add_string(inst, response, XSTR("Failed to create snapshot"));
        response->is_error = TRUE;
        return;
    }

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"processes\":[");
    DWORD count = 0;

    PROCESSENTRY32 pe;
    es_memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (inst->Win32.Process32First(hSnap, &pe)) {
        do {
            // case-insensitive substring match on process name
            char lname[260];
            DWORD k = 0;
            for (; pe.szExeFile[k] && k < 259; k++)
                lname[k] = (pe.szExeFile[k] >= 'A' && pe.szExeFile[k] <= 'Z') ? pe.szExeFile[k] + 32 : pe.szExeFile[k];
            lname[k] = 0;
            // substring search
            BOOL found = FALSE;
            for (DWORD i = 0; lname[i]; i++) {
                BOOL m = TRUE;
                for (DWORD j = 0; j < term_len; j++) {
                    if (lname[i+j] == 0 || lname[i+j] != lower_term[j]) { m = FALSE; break; }
                }
                if (m) { found = TRUE; break; }
            }
            if (!found) continue;
            if (count) j_append_raw(&jb, ",");
            j_append_raw(&jb, "{\"process_id\":");
            j_append_uint(&jb, pe.th32ProcessID);
            j_append_raw(&jb, ",\"parent_process_id\":");
            j_append_uint(&jb, pe.th32ParentProcessID);
            j_append_raw(&jb, ",\"name\":");
            j_append_str(&jb, pe.szExeFile);
            j_append_raw(&jb, "}");
            count++;
        } while (inst->Win32.Process32Next(hSnap, &pe));
    }
    gate_CloseHandle(inst, hSnap);
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
