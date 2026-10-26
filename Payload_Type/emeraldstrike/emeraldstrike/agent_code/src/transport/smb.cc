#include "config.h"
#ifdef SMB_TRANSPORT

#include "common.h"
#include "transport_smb.h"

static HANDLE g_pipe = INVALID_HANDLE_VALUE;

BOOL smb_start_server(PINSTANCE inst) {
    char pipe_path[512] = {0};
    // Build \\.\pipe\<pipename>
    pipe_path[0] = '\\'; pipe_path[1] = '\\'; pipe_path[2] = '.';
    pipe_path[3] = '\\'; pipe_path[4] = 'p'; pipe_path[5] = 'i';
    pipe_path[6] = 'p'; pipe_path[7] = 'e'; pipe_path[8] = '\\';

    int pos = 9;
    for (int i = 0; inst->Smb.pipename[i] && pos < 510; i++)
        pipe_path[pos++] = inst->Smb.pipename[i];
    pipe_path[pos] = 0;

    g_pipe = inst->Win32.CreateNamedPipeA(
        pipe_path,
        0x00000003 | 0x40000000, // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
        0x00000004 | 0x00000002, // PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE
        1,       // max instances
        0x10000, // out buffer
        0x10000, // in buffer
        0,
        NULL
    );

    if (g_pipe == INVALID_HANDLE_VALUE) return FALSE;

    inst->Win32.ConnectNamedPipe(g_pipe, NULL);
    return TRUE;
}

BOOL smb_read(PINSTANCE inst, BYTE** data, DWORD* data_len) {
    if (g_pipe == INVALID_HANDLE_VALUE) return FALSE;

    DWORD avail = 0;
    if (!inst->Win32.PeekNamedPipe(g_pipe, NULL, 0, NULL, &avail, NULL) || avail == 0)
        return FALSE;

    BYTE* buf = (BYTE*)es_malloc(inst, avail);
    if (!buf) return FALSE;

    DWORD read = 0;
    if (!inst->Win32.ReadFile(g_pipe, buf, avail, &read, NULL)) {
        es_free(inst, buf);
        return FALSE;
    }

    *data = buf;
    *data_len = read;
    return TRUE;
}

BOOL smb_write(PINSTANCE inst, BYTE* data, DWORD data_len) {
    if (g_pipe == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written = 0;
    return inst->Win32.WriteFile(g_pipe, data, data_len, &written, NULL);
}

#endif // SMB_TRANSPORT
