#ifndef EMERALDSTRIKE_JSON_OUT_H
#define EMERALDSTRIKE_JSON_OUT_H

#include "common.h"

// Minimal JSON string builder for command handlers. Fixed buffer, no escaping
// beyond quotes/backslashes/control chars (command output fields are trusted-ish:
// file names, API strings). Enough for machine-readable browser scripts.

typedef struct _JSON_BUF {
    char  buf[16384];
    DWORD len;
    BOOL  truncated;
} JSON_BUF;

static void j_init(JSON_BUF* jb) {
    jb->len = 0;
    jb->buf[0] = 0;
    jb->truncated = FALSE;
}

static void j_append_raw(JSON_BUF* jb, const char* s) {
    while (*s) {
        if (jb->len >= sizeof(jb->buf) - 2) { jb->truncated = TRUE; return; }
        jb->buf[jb->len++] = *s++;
    }
    jb->buf[jb->len] = 0;
}

static void j_append_str(JSON_BUF* jb, const char* s) {
    // with quotes + escape
    if (jb->len >= sizeof(jb->buf) - 4) { jb->truncated = TRUE; return; }
    jb->buf[jb->len++] = '"';
    for (; *s; s++) {
        if (jb->len >= sizeof(jb->buf) - 7) { jb->truncated = TRUE; jb->buf[jb->len] = 0; return; }
        char c = *s;
        if (c == '"')  { jb->buf[jb->len++] = '\\'; jb->buf[jb->len++] = '"'; }
        else if (c == '\\') { jb->buf[jb->len++] = '\\'; jb->buf[jb->len++] = '\\'; }
        else if (c == '\n') { jb->buf[jb->len++] = '\\'; jb->buf[jb->len++] = 'n'; }
        else if (c == '\r') { jb->buf[jb->len++] = '\\'; jb->buf[jb->len++] = 'r'; }
        else if (c == '\t') { jb->buf[jb->len++] = '\\'; jb->buf[jb->len++] = 't'; }
        else if ((BYTE)c < 0x20) { jb->buf[jb->len++] = ' '; }
        else jb->buf[jb->len++] = c;
    }
    jb->buf[jb->len++] = '"';
    jb->buf[jb->len] = 0;
}

static void j_append_uint(JSON_BUF* jb, DWORD v) {
    char tmp[16]; int ti = 0;
    if (v == 0) tmp[ti++] = '0';
    while (v > 0) { tmp[ti++] = '0' + (v % 10); v /= 10; }
    for (int j = ti - 1; j >= 0 && jb->len < sizeof(jb->buf) - 2; j--)
        jb->buf[jb->len++] = tmp[j];
    jb->buf[jb->len] = 0;
}

static void j_append_u64(JSON_BUF* jb, unsigned __int64 v) {
    // libgcc-free: PIC x86 link has no __udivdi3/__umoddi3, so 64-bit / and %
    // cannot be used. Shift-subtract long division by 10 (per digit).
    char tmp[24]; int ti = 0;
    if (v == 0) tmp[ti++] = '0';
    while (v > 0 && ti < 23) {
        unsigned __int64 q = 0, r = 0;
        for (int i = 63; i >= 0; i--) {
            r = (r << 1) | ((v >> i) & 1ULL);
            if (r >= 10) { r -= 10; q |= (1ULL << i); }
        }
        tmp[ti++] = '0' + (char)r;
        v = q;
    }
    for (int k = ti - 1; k >= 0 && jb->len < sizeof(jb->buf) - 2; k--)
        jb->buf[jb->len++] = tmp[k];
    jb->buf[jb->len] = 0;
}

static void j_append_bool(JSON_BUF* jb, BOOL v) {
    j_append_raw(jb, v ? "true" : "false");
}

#endif
