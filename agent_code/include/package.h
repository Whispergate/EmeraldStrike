#ifndef EMERALDSTRIKE_PACKAGE_H
#define EMERALDSTRIKE_PACKAGE_H

#include "common.h"

typedef struct _PACKAGE {
    BYTE*  buffer;
    DWORD  length;
    DWORD  capacity;
    DWORD  task_id;
    BOOL   is_error;
} PACKAGE, *PPACKAGE;

PPACKAGE package_create(PINSTANCE inst);
VOID     package_add_int32(PINSTANCE inst, PPACKAGE pkg, DWORD val);
VOID     package_add_int16(PINSTANCE inst, PPACKAGE pkg, SHORT val);
VOID     package_add_bytes(PINSTANCE inst, PPACKAGE pkg, const BYTE* buf, DWORD len);
VOID     package_add_lenprefixed(PINSTANCE inst, PPACKAGE pkg, const BYTE* buf, DWORD len);
VOID     package_add_string(PINSTANCE inst, PPACKAGE pkg, const char* str);
BYTE*    package_get_data(PPACKAGE pkg, DWORD* out_len);
VOID     package_destroy(PINSTANCE inst, PPACKAGE pkg);

#endif // EMERALDSTRIKE_PACKAGE_H
