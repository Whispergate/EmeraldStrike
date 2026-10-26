NAME   := emeraldstrike

CCACHE := $(shell command -v ccache 2>/dev/null)
CCX64  := $(CCACHE) clang -target x86_64-w64-mingw32
CCX86  := $(CCACHE) clang -target i686-w64-mingw32
ASMCC  := nasm

CFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1 -s -w -mno-sse
CFLAGS += -ffunction-sections -fno-zero-initialized-in-bss -falign-jumps=1 -falign-labels=1 -fno-jump-tables
CFLAGS += -Wl,-s,--strip-all,--enable-stdcall-fixup -masm=intel -fno-exceptions
CFLAGS += -fms-extensions -fno-builtin -Iinclude -Wl,-Tscripts/linker.ld

# Detect mingw-w64 C++ headers for cross-compilation
GCC_X64_CXX := $(wildcard /usr/lib/gcc/x86_64-w64-mingw32/*/include/c++)
GCC_X86_CXX := $(wildcard /usr/lib/gcc/i686-w64-mingw32/*/include/c++)
ifneq ($(GCC_X64_CXX),)
  GCC_X64_DIR := $(firstword $(GCC_X64_CXX))
  CFLAGS_X64_INC := -isystem $(GCC_X64_DIR) -isystem $(GCC_X64_DIR)/x86_64-w64-mingw32
endif
ifneq ($(GCC_X86_CXX),)
  GCC_X86_DIR := $(firstword $(GCC_X86_CXX))
  CFLAGS_X86_INC := -isystem $(GCC_X86_DIR) -isystem $(GCC_X86_DIR)/i686-w64-mingw32
endif

# MSYS2/Windows sysroot detection
MSYS2_X64_HDR := $(wildcard C:/msys64/mingw64/include/windows.h)
MSYS2_X86_HDR := $(wildcard C:/msys64/mingw32/include/windows.h)
MSYS2_X64_CXX := $(wildcard C:/msys64/mingw64/include/c++/*)
MSYS2_X86_CXX := $(wildcard C:/msys64/mingw32/include/c++/*)
ifneq ($(MSYS2_X64_HDR),)
  ifeq ($(CFLAGS_X64_INC),)
    CFLAGS_X64_INC := --sysroot=C:/msys64/mingw64
    ifneq ($(MSYS2_X64_CXX),)
      CFLAGS_X64_INC += -isystem $(firstword $(MSYS2_X64_CXX)) -isystem $(firstword $(MSYS2_X64_CXX))/x86_64-w64-mingw32
    endif
  endif
endif
ifneq ($(MSYS2_X86_HDR),)
  ifeq ($(CFLAGS_X86_INC),)
    CFLAGS_X86_INC := --sysroot=C:/msys64/mingw32
    ifneq ($(MSYS2_X86_CXX),)
      CFLAGS_X86_INC += -isystem $(firstword $(MSYS2_X86_CXX)) -isystem $(firstword $(MSYS2_X86_CXX))/i686-w64-mingw32
    endif
  endif
endif

DEFINES ?=
CFLAGS  += $(DEFINES)

SRC    := $(wildcard src/*.cc) $(wildcard src/commands/*.cc) $(wildcard src/transport/*.cc) $(wildcard src/evasion/*.cc)
OBJ64  := $(SRC:%.cc=%.x64.obj)
OBJ86  := $(SRC:%.cc=%.x86.obj)

# DLL mode flags - proper PE DLL for UDRL loading (no PIC linker script, relocations preserved)
DLLCFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20
DLLCFLAGS += -fno-ident -fpack-struct=8 -w -mno-sse -fno-jump-tables
DLLCFLAGS += -masm=intel -fno-exceptions -fms-extensions -Iinclude -DDLL_MODE
DLLCFLAGS += -fno-builtin $(DEFINES)
DLLOBJS64 := $(SRC:%.cc=%.dll64.obj)

release: x64 x86
debug:   x64-debug x86-debug

x64-debug: CFLAGS += -DDEBUG
x64-debug: x64

x86-debug: CFLAGS += -DDEBUG
x86-debug: x86

x64: nasm64 $(OBJ64)
	@ echo "compiling x64 project"
	@ $(CCX64) bin/obj/*.x64.obj -o bin/$(NAME).x64.exe $(CFLAGS) $(CFLAGS_X64_INC)
	@ strip --strip-all bin/$(NAME).x64.exe
	@ objcopy --dump-section .text=bin/$(NAME).x64.bin bin/$(NAME).x64.exe

x86: nasm86 $(OBJ86)
	@ echo "compiling x86 project"
	@ $(CCX86) bin/obj/*.x86.obj -o bin/$(NAME).x86.exe $(CFLAGS) $(CFLAGS_X86_INC)
	@ strip --strip-all bin/$(NAME).x86.exe
	@ objcopy --dump-section .text=bin/$(NAME).x86.bin bin/$(NAME).x86.exe

dll-x64: $(DLLOBJS64)
	@ echo "compiling x64 DLL for UDRL"
	@ $(CCX64) bin/obj/*.dll64.obj -o bin/$(NAME).x64.dll -shared $(DLLCFLAGS) $(CFLAGS_X64_INC) \
	  -Wl,-s,--enable-stdcall-fixup,-e,DllMain,--exclude-all-symbols,-Map=bin/$(NAME).x64.map
	@ strip --strip-unneeded bin/$(NAME).x64.dll

%.x64.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX64) -o bin/obj/$(notdir $@) -c $< $(CFLAGS) $(CFLAGS_X64_INC)

%.x86.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX86) -o bin/obj/$(notdir $@) -c $< $(CFLAGS) $(CFLAGS_X86_INC)

%.dll64.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@) [DLL]"
	@ $(CCX64) -o bin/obj/$(notdir $@) -c $< $(DLLCFLAGS) $(CFLAGS_X64_INC)

nasm64:
	@ $(ASMCC) -f win64 src/asm/entry.x64.asm -o bin/obj/entry.x64.obj

nasm86:
	@ $(ASMCC) -f win32 src/asm/entry.x86.asm -o bin/obj/entry.x86.obj

clean:
	@ rm -f bin/obj/*.obj bin/*.exe bin/*.bin bin/*.dll

.PHONY: release debug x64 x86 x64-debug x86-debug dll-x64 nasm64 nasm86 clean
