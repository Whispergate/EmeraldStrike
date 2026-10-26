#include "package.h"

#define PKG_INITIAL_CAP 1024

static VOID _ensure_capacity(PINSTANCE inst, PPACKAGE pkg, DWORD extra) {
    if (pkg->length + extra <= pkg->capacity) return;
    DWORD new_cap = pkg->capacity * 2;
    while (new_cap < pkg->length + extra) new_cap *= 2;
    BYTE* new_buf = (BYTE*)es_realloc(inst, pkg->buffer, new_cap);
    if (new_buf) {
        pkg->buffer = new_buf;
        pkg->capacity = new_cap;
    }
}

PPACKAGE package_create(PINSTANCE inst) {
    PPACKAGE pkg = (PPACKAGE)es_malloc(inst, sizeof(PACKAGE));
    if (!pkg) return NULL;
    pkg->buffer   = (BYTE*)es_malloc(inst, PKG_INITIAL_CAP);
    pkg->length   = 0;
    pkg->capacity = PKG_INITIAL_CAP;
    pkg->task_id  = 0;
    pkg->is_error = FALSE;
    return pkg;
}

VOID package_add_int32(PINSTANCE inst, PPACKAGE pkg, DWORD val) {
    _ensure_capacity(inst, pkg, 4);
    pkg->buffer[pkg->length++] = (val >> 24) & 0xFF;
    pkg->buffer[pkg->length++] = (val >> 16) & 0xFF;
    pkg->buffer[pkg->length++] = (val >> 8)  & 0xFF;
    pkg->buffer[pkg->length++] = val & 0xFF;
}

VOID package_add_int16(PINSTANCE inst, PPACKAGE pkg, SHORT val) {
    _ensure_capacity(inst, pkg, 2);
    pkg->buffer[pkg->length++] = (val >> 8) & 0xFF;
    pkg->buffer[pkg->length++] = val & 0xFF;
}

VOID package_add_bytes(PINSTANCE inst, PPACKAGE pkg, const BYTE* buf, DWORD len) {
    _ensure_capacity(inst, pkg, len);
    es_memcpy(pkg->buffer + pkg->length, (PVOID)buf, len);
    pkg->length += len;
}

VOID package_add_lenprefixed(PINSTANCE inst, PPACKAGE pkg, const BYTE* buf, DWORD len) {
    package_add_int32(inst, pkg, len);
    _ensure_capacity(inst, pkg, len);
    es_memcpy(pkg->buffer + pkg->length, (PVOID)buf, len);
    pkg->length += len;
}

VOID package_add_string(PINSTANCE inst, PPACKAGE pkg, const char* str) {
    DWORD len = es_strlen(str);
    package_add_bytes(inst, pkg, (const BYTE*)str, len);
}

BYTE* package_get_data(PPACKAGE pkg, DWORD* out_len) {
    if (out_len) *out_len = pkg->length;
    return pkg->buffer;
}

VOID package_destroy(PINSTANCE inst, PPACKAGE pkg) {
    if (!pkg) return;
    if (pkg->buffer) es_free(inst, pkg->buffer);
    es_free(inst, pkg);
}
