+++
title = "evasion"
chapter = false
weight = 5
+++

## Built-in Evasion

EmeraldStrike includes several evasion capabilities that can be configured at build time.

### PIC Shellcode Architecture

The agent is compiled as position-independent code (PIC) using a custom linker script that merges all sections (`.text`, `.rdata`, `.data`, `.bss`) into a single `.text` section. The entry point is an ASM stub that resolves the instance pointer via RIP-relative addressing.

All API calls go through an indirect function pointer table (`inst->Win32`) resolved at runtime via DJB2 hash lookups - no static imports appear in the binary.

All string literals use the `xstr` / `XSTR` compile-time encryption macro - strings are decrypted on the stack at point of use and do not appear in the binary's static data.

### DLL Mode (UDRL Compatible)

The agent can also be compiled as a standard Windows DLL via `make dll-x64`. This mode:

- Preserves PE relocations for proper UDRL base relocation processing
- Handles the full UDRL protocol: `DLL_BEACON_USER_DATA` (0x0d) -> `DLL_PROCESS_ATTACH` (0x01) -> `DLL_BEACON_START` (0x04)
- Stores `USER_DATA` and `ALLOCATED_MEMORY` information from the UDRL
- Falls back to standalone operation if loaded without a UDRL (spawns its own agent thread on `DLL_PROCESS_ATTACH`)

### Sleep Masking

EmeraldStrike supports multiple sleep mask modes selected at build time:

| Mode | Value | Description |
|------|-------|-------------|
| None | `MASK_NONE` | Plain sleep - no obfuscation |
| Default | `MASK_DEFAULT` | XOR-based heap and data masking during sleep |
| Ekko | `MASK_EKKO` | Timer-queue ROP chain sleep with `SystemFunction032` encryption/decryption |
| UDRL | `MASK_UDRL` | Sleepmask provided as embedded COFF, executed during sleep cycles |

The Ekko technique uses `NtCreateTimerQueue`, `RtlCreateTimer`, and ROP gadgets to encrypt agent memory during sleep without requiring an executable sleep mask region.

### Beacon Gate

When `BEACON_GATE_ENABLED=1`, Win32 API calls from the agent are routed through gate wrapper functions in `beacon_gate.cc`. These wrappers populate a `FUNCTION_CALL` struct and invoke the sleepmask's `BeaconGateHandler`, allowing the sleepmask COFF to perform the actual Win32 call. This enables:

- Call stack spoofing (the Win32 call originates from the sleepmask context, not the agent's code)
- Indirect syscalls via the sleepmask
- CFG (Control Flow Guard) compatibility

Beacon Gate requires `MASK_UDRL` mode with a sleepmask COFF that implements the gate handler.

### Configurable Injection Techniques

The injection technique is selected at compile time via `INJECTION_TECHNIQUE`:

| Technique | Constant | Method |
|-----------|----------|--------|
| CreateRemoteThread (default) | `INJECT_CRT` | `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> `CreateRemoteThread` |
| APC Early Bird | `INJECT_APC` | Same alloc/write/protect + suspended `SleepEx` thread + `QueueUserAPC` + `ResumeThread` |
| NtCreateSection | `INJECT_SECTION` | Shared section mapping - no `VirtualAllocEx`/`WriteProcessMemory` telemetry |
| Custom | `INJECT_CUSTOM` | Operator-defined (defaults to CRT) |

### Conditional Compilation

Every command is wrapped in `#ifdef INCLUDE_CMD_<NAME>` guards. The builder stamps only the commands selected during payload generation into `config.h`, reducing the binary's code surface and eliminating unused API references.

## Build-Time Considerations

### Debug vs Release

Debug builds (`make x64-debug`) define the `DEBUG` macro, which enables `OutputDebugStringA` diagnostic messages via the `DBG()` macro. Release builds (`make x64`) strip all debug output.

{{% notice warning %}}
Never deploy debug builds in production engagements. Debug strings reveal internal agent state, command names, and error details to anyone monitoring `OutputDebugString` output (e.g., DebugView, attached debugger).
{{% /notice %}}

### PIC Constraints

The PIC build mode imposes several constraints:

- No CRT dependency - all memory operations use custom `es_memcpy`/`es_memset`/`es_malloc`/`es_free`
- No static initializers - global variables must be explicitly initialized at function entry
- No C++ exceptions - compiled with `-fno-exceptions`
- No jump tables - compiled with `-fno-jump-tables` to avoid `.rdata` references
- Manual integer-to-string conversion throughout (no `sprintf`/`snprintf`)
- ANSI API variants used in most commands (`CreateFileA`, `FindFirstFileA`, etc.)
