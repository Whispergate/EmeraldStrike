#ifndef EMERALDSTRIKE_PARSER_H
#define EMERALDSTRIKE_PARSER_H

#include "common.h"

typedef struct _PARSER {
    BYTE* buffer;
    DWORD length;
    DWORD position;
} PARSER, *PPARSER;

VOID  parser_init(PPARSER p, BYTE* buf, DWORD len);
DWORD parser_int32(PPARSER p);
SHORT parser_int16(PPARSER p);
BYTE* parser_bytes(PPARSER p, DWORD* out_len);
char* parser_string(PPARSER p, DWORD* out_len);

#endif // EMERALDSTRIKE_PARSER_H
