+++
title = "UDRL Development"
chapter = false
weight = 2
+++

# UDRL Development: Cobalt Strike vs Mythic (EmeraldStrike)

EmeraldStrike's UDRL kit is a direct port of the CS 4.12/4.13 `udrl_sleepmask_dev` reference. This document covers the architectural quirks, gotchas, and divergences you will encounter developing the UDRL and sleepmask for Mythic instead of CS.

---

## Build Pipeline

### Cobalt Strike

CS uses Aggressor (CNA) scripts to trigger UDRL builds. The operator uploads a kit ZIP through the Aggressor client, which hands the files to the teamserver. The teamserver compiles the loader and sleepmask, links them with the beacon DLL, and produces the final payload.

### Mythic (EmeraldStrike)

`builder.py` replaces the Aggressor pipeline entirely:

1. The operator uploads the UDRL kit as a ZIP via the Mythic UI (build parameter `udrl_vs_file`).
2. `_extract_udrl_kit()` extracts it, locating `loader/` and `mask/` one level deep.
3. `_build_sleepmask_coff()` runs `make` in `mask/` to produce `sleepmask.x64.o`.
4. The COFF bytes are embedded into `config.h` as a C byte array literal (`SLEEPMASK_COFF[]`). The agent DLL carries its own sleepmask inline.
5. The agent is compiled as a DLL (`make dll-x64`).
6. `_link_with_udrl_vs()` runs `make` in `loader/` and concatenates `loader_sc + dll_bytes`.

The final payload is raw shellcode: the UDRL PIC loader followed immediately by the beacon DLL.

### Key Difference

CS handles sleepmask COFF loading internally within the beacon binary. In EmeraldStrike, the sleepmask COFF is embedded at build time and the agent must load it itself. This means any change to the sleepmask requires a full payload rebuild.

---

## Payload Layout

```
[ UDRL PIC Shellcode ][ Beacon DLL ]
|<-- loader.bin ----->|<-- agent -->|
```

The loader finds the DLL at `Instance()->Base.Buffer + Instance()->Base.Length` - the DLL is appended directly after the `STARDUST-END` marker that terminates the PIC `.text` section.

The `build.py` extraction script finds `STARDUST-END` in the linked EXE and extracts only the `.text` section up to that point.

---

## Two Compilation Modes: PIC vs COFF

The `common/` directory contains shared code (`Timers.c`, `Cfg.c`, `Print.c`) compiled in two different modes. The `PIC` preprocessor define is the toggle.

### Loader (PIC mode: `-DPIC`)

- Compiler: `x86_64-w64-mingw32-g++`
- Output: raw PIC shellcode (`.text` section extracted)
- Instance data accessed via TLS egghunter (`STARDUST_INSTANCE` → `ResolveInstanceAddr()`)
- API calls go through function pointers: `API(VirtualProtect)` → `Instance()->Win32.VirtualProtect`
- `CUSTOM_DATA` accessed via `CDATA` macro → `Instance()->cData`
- All functions placed in `.text$B` via `FUNC` → `__attribute__((section(".text$B")))`

### Sleepmask (COFF mode: no `-DPIC`)

- Compiler: `x86_64-w64-mingw32-gcc`
- Output: relocatable COFF object (`.o`)
- No instance struct - `cData` is a file-scope global
- API calls use raw function names: `API(VirtualProtect)` → `VirtualProtect` (dllimport, patched by objcopy)
- `STARDUST_INSTANCE`, `FUNC`, and `CDATA` expand to nothing
- Shared `.c` files are `#include`d directly into `sleepmask.h` (source-level include, single translation unit)

### The Guards

In each shared source file:

```c
#ifdef PIC
    #include <Common.h>
#else
    #include <shared.h>
    #define FUNC
    #define STARDUST_INSTANCE
    #define API(x) x
    #define CDATA
#endif
```

In `shared.h`, the global `cData` declaration is suppressed under PIC:

```c
#ifndef PIC
EXTERN_C PCUSTOM_DATA cData;
#endif
```

---

## COFF Symbol Patching

The sleepmask COFF needs its Win32 imports resolved by Beacon's COFF loader at runtime. Beacon expects BOF-style symbols: `__imp_MODULE$Function`.

### Pipeline

1. `sleepmask.h` declares every API function via `__declspec(dllimport)`, generating `__imp_<func>` relocations.
2. `genimports.py` reads `API_LIST` from `shared.h` and generates `sleepmask_symbols.txt`.
3. `objcopy --redefine-syms` patches the `.o` in-place, renaming e.g. `__imp_VirtualProtect` → `__imp_KERNEL32$VirtualProtect`.

If you add a new API call to the sleepmask, you must add a corresponding `API_ENTRY(func, Module)` to `API_LIST` in `shared.h`. The `genimports.py` script and Makefile handle the rest.

---

## COFF Globals Bug

**Static initialization does not work reliably in COFF objects.**

```c
INT iCtx = { 0 };     // ← NOT guaranteed to be zero at runtime
PVOID ptr = { 0 };     // ← same problem
```

The COFF loader skips COMMON symbol relocations, so the `= { 0 }` initializer may never take effect. Globals in COFF objects can contain garbage from whatever memory they land in.

### Rule

Always explicitly initialize globals at the entry point of the COFF before use:

```c
// In sleep_mask():
bBofVpCall = FALSE;
cData = *(PCUSTOM_DATA*)BeaconGetCustomUserData();
```

This applies to all globals in `mask/src/main.c`. It does NOT apply to struct fields in heap-allocated memory (like `cData->iCtx`), which are zeroed by `calloc` or explicit `memset`.

---

## CUSTOM_DATA Struct

`CUSTOM_DATA` is the shared state between the UDRL loader and the sleepmask. It lives on the heap, allocated by the loader and passed through `USER_DATA.custom[]`.

### Access Patterns

**Loader (PIC):** `Instance()->cData` (via the `CDATA` macro creating a local `cData` variable)

**Sleepmask (COFF):** Global `PCUSTOM_DATA cData`, populated once per `sleep_mask()` call:
```c
cData = *(PCUSTOM_DATA*)BeaconGetCustomUserData();
```

### Layout Sensitivity

New fields **must** go at the END of the struct. Both the loader and sleepmask are compiled independently and share the struct definition through `shared.h`. Inserting a field in the middle shifts all subsequent offsets and will cause silent corruption.

### Key Fields

| Field | Purpose |
|-------|---------|
| `pStompBeacon` | Base of beacon memory in the stomped sacrificial DLL |
| `pStompSleepmask` | Base of sleepmask region (immediately after beacon) |
| `pStompBof` | Base of BOF region (after sleepmask) |
| `pSacDllBase` | Base of the loaded sacrificial DLL |
| `pBackup` / `pBackupPdata` | Backup buffers for memory/pdata restored after sleep |
| `pContexts` / `pApiArgs` / `pApiResults` | Timer-queue ROP chain state |
| `iCtx` | Current CONTEXT index for `SetupTimerContext` |
| `key[16]` | Random RC4 key for SystemFunction032 encryption during sleep |
| `hSacSection` | Duplicated section handle for unmap/remap cycle |
| `bFirstSleep` | One-shot flag for first-sleep initialization |

---

## USER_DATA and Beacon Initialization

### CS

The teamserver constructs `USER_DATA` internally and passes it to beacon through its own loading mechanism.

### EmeraldStrike

The UDRL loader constructs `USER_DATA` manually in `Main()`:

```c
USER_DATA userData = { 0 };
userData.version = 0x041200;  // CS 4.12 compatibility
MmCopy(userData.custom, &cData, sizeof(PVOID));  // store CUSTOM_DATA pointer
userData.allocatedMemory = &allocatedMemory;
```

The `custom[32]` field carries the `CUSTOM_DATA` pointer. The sleepmask later retrieves it:

```c
cData = *(PCUSTOM_DATA*)BeaconGetCustomUserData();
```

### DllMain Call Sequence

Three calls, in order:

1. `DllMain(0, DLL_BEACON_USER_DATA, &userData)` - reason `0x0d`, passes the USER_DATA
2. `DllMain(pStompBeacon, DLL_PROCESS_ATTACH, NULL)` - reason `0x01`, initializes the agent
3. `NtContinue(&MainThreadCtx)` with `Rip=DllMain`, `Rdx=DLL_BEACON_START` - reason `0x04`, starts the agent main loop with a clean callstack

The third call uses `NtContinue` instead of a direct function call to spoof the thread callstack. `MainThreadCtx.Rsp` is set to the `BaseThreadInitThunk` return address found by walking the thread's stack, so the beacon thread unwinds cleanly through `BaseThreadInitThunk` → `RtlUserThreadStart`.

---

## Timer-Queue Execution (Ekko)

The sleepmask uses a timer-queue ROP chain to execute API calls during sleep without the sleepmask's own code appearing on the call stack.

### Architecture

- `InitializeTimers()` - creates a timer queue, events, captures a worker thread CONTEXT via `RtlCaptureContext`, duplicates it across `NUM_TIMER_CONTEXTS` slots, queues the initial `WaitForSingleObjectEx`.
- `SETUP_CONTEXT(func, args...)` - macro that expands through `FILL_NULLS` → `EXPAND_ARGS_10` → `SetupTimerContext()`, which populates `cData->pContexts[cData->iCtx]` with the function and args, then increments `cData->iCtx`.
- `SetupTimerStack()` - builds the ROP stack frames using the three gadgets (`pAddRspGadget`, `pMovRbxPtrGadget`, `pStackArgsGadget`) so each timer fires `NtContinue` and the called function's extra stack arguments are in place.
- `QueueAndExecuteTimers()` - adds the final `SetEvent`, calls `SetupTimerStack`, queues all `NtContinue` timers, fires `NtSignalAndWaitForSingleObject`, cleans up, resets `cData->iCtx` to 0.

### NUM_TIMER_CONTEXTS

The mask Makefile counts `SETUP_CONTEXT` calls in `src/main.c` and updates `NUM_TIMER_CONTEXTS` in `shared.h` automatically. If you add or remove `SETUP_CONTEXT` calls, rebuild from the mask Makefile to keep this in sync.

### Common Mistakes

**Don't duplicate InitializeTimers inline.** `Ekko()` should call `InitializeTimers()` for setup and `QueueAndExecuteTimers()` for execution. Duplicating the timer infrastructure inline (creating local Queue/events, capturing context, manually queuing timers) leads to mismatched state - the SETUP_CONTEXT calls write to `cData->iCtx` while inline code reads a different counter.

**Don't mix global and struct-field counters.** `iCtx` was moved to `cData->iCtx`. All references to `iCtx` in the Ekko flow must use `cData->iCtx`. A stale global `iCtx` will stay at 0 forever since `SetupTimerContext` only increments the struct field.

---

## Callstack Spoofing

The UDRL calls `DllMain(DLL_BEACON_START)` via `NtContinue` to produce a clean thread callstack that unwinds through `BaseThreadInitThunk` → `RtlUserThreadStart`.

### FindBaseThreadInitThunkReturn

Walks the current thread's stack (starting from `NtCurrentTeb()->NtTib.StackBase`) looking for return addresses that fall within `BaseThreadInitThunk` and `RtlUserThreadStart`. Returns the stack address of the `BaseThreadInitThunk` return, which becomes `MainThreadCtx.Rsp`.

Both functions need `API_ENTRY` declarations in the `API_LIST` and function prototypes in `Native.h`.

### NtContinue Ordering

`NtContinue` replaces the current thread context and **never returns**. The CONTEXT struct must be fully populated (Rip, Rcx, Rdx, R8, Rsp, ContextFlags) **before** the call. Any code after `NtContinue` is dead code.

### Segment Register Crash

`CONTEXT_FULL` includes `CONTEXT_CONTROL`, which restores `SegCs` and `SegSs`. A zero-initialized CONTEXT (`= { 0 }`) has `SegCs=0` and `SegSs=0` - loading these triggers a #GP fault.

**Fix:** Call `RtlCaptureContext(&MainThreadCtx)` first to fill the struct with valid segment registers, EFlags, and floating point state, then override the fields you need (Rip, Rcx, Rdx, R8, Rsp, ContextFlags). Save and restore Rsp around the capture since `RtlCaptureContext` clobbers it:

```c
DWORD64 savedRsp = MainThreadCtx.Rsp;
RtlCaptureContext(&MainThreadCtx);
MainThreadCtx.Rsp = savedRsp;
MainThreadCtx.Rip = ...;
```

This matches the pattern used by `InitializeTimers()` for the Ekko timer chain - it captures a worker thread context via `RtlCaptureContext`, copies it to all CONTEXT slots, then modifies Rip/Rcx/etc. per slot.

### Dangling USER_DATA Pointer

The UDRL loader's `Main()` allocates `USER_DATA userData` as a local variable on the stack, passes it to `DllMain(0, DLL_BEACON_USER_DATA, &userData)`, then calls `NtContinue` which repositions Rsp near StackBase. The agent's new call chain (HTTP I/O, etc.) grows the stack downward from StackBase, overwriting the loader's old stack frame where `userData` lived.

If the DLL_BEACON_USER_DATA handler stores only the pointer (`inst->pUserData = lpReserved`), any later access - especially `BeaconGetCustomUserData()` returning `inst->pUserData->custom` for the sleepmask - reads from corrupted stack memory and crashes.

**Fix:** Copy the USER_DATA struct by value into INSTANCE at DLL_BEACON_USER_DATA time:

```c
case DLL_BEACON_USER_DATA:
    if (lpReserved) {
        es_memcpy(&inst->savedUserData, lpReserved, sizeof(USER_DATA));
        inst->pUserData = &inst->savedUserData;
    }
    break;
```

This only matters when the loader enters `DllMain(DLL_BEACON_START)` via `NtContinue` (which repositions the stack). With a direct call, the loader's stack frame remains valid.

---

## Module Stomping and CFG

The loader stomps a signed DLL (sacrificial DLL) with beacon code so that:
- Memory is `MEM_IMAGE` type, not `MEM_PRIVATE`
- The code resides within a legitimate module's address range
- Control Flow Guard (CFG) validates calls because they target addresses within a trusted module

### CFG Bitmap Management

The loader checks the CFG policy via `GetProcessMitigationPolicy` and, if CFG is enabled, calls `SetProcessValidCallTargets` to add the stomped entry points to the CFG bitmap. This happens:
- Once at load time for the beacon entry point
- During each Ekko sleep cycle (the sacrificial DLL is unmapped/remapped, so CFG entries must be re-added)
- When `SetThreadContext` targets beacon memory (for injection), the sleepmask intercepts the `SETTHREADCONTEXT` gate call and adds the target address to CFG before `ResumeThread`

---

## Debugging Tips

### Debug Output Prefixes

- `[DEBUG] UDRL::` - messages from loader code (PIC)
- `[DEBUG] Sleepmask::` - messages from sleepmask code (COFF)

Both use the `PRINT` macro, which is conditionally compiled with different prefixes via `shared.h`.

### DBG Macro

The loader's `DBG` macro takes exactly 2 arguments: `DBG(inst, tag)` - an instance and a string tag. It is NOT printf-style.

### Common Crash Causes

1. **iCtx never increments** - using a global `iCtx` instead of `cData->iCtx`; `SetupTimerContext` only writes to the struct field.
2. **NtContinue with uninitialized CONTEXT** - populate Rip/Rcx/Rdx/R8/Rsp/ContextFlags before calling.
3. **Sleepmask globals contain garbage** - COFF loader doesn't honor `= { 0 }` initializers; always set globals explicitly at `sleep_mask()` entry.
4. **NULL pApiResults in InitializeTimers** - if `pContexts`/`pApiArgs`/`pApiResults` are allocated in `bFirstSleep` after `MapBofUnwindInfo` (which calls `InitializeTimers`), move the allocation before the map call.
5. **CUSTOM_DATA field inserted in the middle** - shifts all subsequent offsets; new fields go at the end only.
6. **NUM_TIMER_CONTEXTS out of sync** - add/remove `SETUP_CONTEXT` calls without rebuilding from the mask Makefile.
7. **Dangling USER_DATA pointer after NtContinue** - `inst->pUserData` points to the loader's stack-local `userData`; NtContinue repositions Rsp near StackBase, and the agent's call chain overwrites the old frame. Copy USER_DATA by value into INSTANCE.
8. **allocatedMemory wiped by agent_init / populate_beacon_info** - `agent_init()` and `populate_beacon_info()` both do `es_memset(&inst->BeaconInfo, 0, ...)`, destroying the `allocatedMemory` regions set by `DLL_BEACON_USER_DATA`. This causes `find_sleepmask_region()` to return NULL, so the sleepmask COFF falls back to VirtualAlloc (heap) instead of the stomped region. Save and restore `allocatedMemory` across the memset.

### Useful Breakpoints (x64dbg)

- `RtlCreateTimerQueue` - first timer-related call in both `InitializeTimers` and `Ekko`
- `NtSignalAndWaitForSingleObject` - fires the timer chain
- `NtContinue` - each timer fires through this
- `SystemFunction032` - RC4 encrypt/decrypt of beacon memory
