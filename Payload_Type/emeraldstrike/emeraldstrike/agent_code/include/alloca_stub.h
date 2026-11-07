#ifndef EMERALDSTRIKE_ALLOCA_H
#define EMERALDSTRIKE_ALLOCA_H

// x86 _alloca stack probe stub for -nostdlib builds.
// clang emits calls to _alloca when a function's stack frame exceeds 4096
// bytes (one page). The probe walks the stack page-by-page to trigger guard
// page exceptions so the OS can grow the stack. Without it, a large stack
// frame that skips the guard page causes a hard fault.
//
// On x64 this is handled by __chkstk which clang resolves differently;
// only x86 needs this stub.

#ifndef _WIN64

// _alloca(eax = bytes to allocate)
// Must probe each page from current ESP downward, then adjust ESP.
// Returns new ESP in EAX. Preserves ECX (callee convention).
__attribute__((naked, used))
void _alloca(void) {
    __asm__ volatile(
        "push ecx\n"
        "cmp eax, 4096\n"       // if size <= page, skip probe loop
        "lea ecx, [esp + 8]\n"  // ecx = original stack (past push ecx + ret addr)
        "jbe .Lalloca_done\n"
        ".Lalloca_loop:\n"
        "sub ecx, 4096\n"
        "test dword ptr [ecx], ecx\n"  // touch the page (probe)
        "sub eax, 4096\n"
        "cmp eax, 4096\n"
        "ja .Lalloca_loop\n"
        ".Lalloca_done:\n"
        "sub ecx, eax\n"       // ecx = final stack position
        "test dword ptr [ecx], ecx\n"  // probe final page
        "mov eax, esp\n"       // save old esp
        "mov esp, ecx\n"       // commit the allocation
        "mov ecx, dword ptr [eax]\n"  // restore ecx (was pushed first)
        "push dword ptr [eax + 4]\n"  // push return address
        "ret\n"
    );
}

#endif // !_WIN64
#endif // EMERALDSTRIKE_ALLOCA_H
