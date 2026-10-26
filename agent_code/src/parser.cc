#include "parser.h"

VOID parser_init(PPARSER p, BYTE* buf, DWORD len) {
    p->buffer   = buf;
    p->length   = len;
    p->position = 0;
}

DWORD parser_int32(PPARSER p) {
    if (p->position + 4 > p->length) return 0;
    BYTE* b = p->buffer + p->position;
    DWORD val = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    p->position += 4;
    return val;
}

SHORT parser_int16(PPARSER p) {
    if (p->position + 2 > p->length) return 0;
    BYTE* b = p->buffer + p->position;
    SHORT val = (b[0] << 8) | b[1];
    p->position += 2;
    return val;
}

BYTE* parser_bytes(PPARSER p, DWORD* out_len) {
    DWORD len = parser_int32(p);
    if (p->position + len > p->length) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    BYTE* ptr = p->buffer + p->position;
    p->position += len;
    if (out_len) *out_len = len;
    return ptr;
}

char* parser_string(PPARSER p, DWORD* out_len) {
    return (char*)parser_bytes(p, out_len);
}
