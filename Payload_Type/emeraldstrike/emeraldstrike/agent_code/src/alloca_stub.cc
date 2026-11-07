// x86 _alloca stack probe for -nostdlib builds.
// clang/mingw emits _alloca calls when a stack frame exceeds 4096 bytes.
// The probe touches each page downward so the OS grows the committed stack.
// x64 uses __chkstk via a different mechanism; this compiles to nothing there.

#ifndef _WIN64

// The linker symbol is `__alloca` (C name `_alloca` with i686 underscore prefix).
// Using top-level __asm__ avoids conflicting with mingw's _alloca prototype.
__asm__(
    ".globl __alloca\n"
    ".globl ___alloca\n"
    "__alloca:\n"
    "___alloca:\n"
    "    push %ecx\n"
    "    cmpl $4096, %eax\n"
    "    leal 8(%esp), %ecx\n"
    "    jbe .Lalloca_last\n"
    ".Lalloca_probe:\n"
    "    subl $4096, %ecx\n"
    "    testl %ecx, (%ecx)\n"
    "    subl $4096, %eax\n"
    "    cmpl $4096, %eax\n"
    "    ja .Lalloca_probe\n"
    ".Lalloca_last:\n"
    "    subl %eax, %ecx\n"
    "    testl %ecx, (%ecx)\n"
    "    movl %esp, %eax\n"
    "    movl %ecx, %esp\n"
    "    movl (%eax), %ecx\n"
    "    pushl 4(%eax)\n"
    "    ret\n"
);

#endif // !_WIN64
