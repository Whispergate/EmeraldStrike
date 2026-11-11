# EmeraldStrike

EmeraldStrike is a Windows post-exploitation agent for [Mythic](https://github.com/its-a-feature/Mythic). It compiles as position-independent code (PIC) shellcode compatible with Cobalt Strike 4.13 loaders, sleepmasks, and BOF tooling.

The agent is written in C/C++20 and cross-compiled with Clang + mingw-w64. It resolves all Win32 APIs at runtime via DJB2 hash walking the PEB, communicates over a binary TLV wire protocol with AES-256-CBC encryption, and supports HTTP (WinINet or WinHTTP), SMB named-pipe, and Azure Blob Storage transports.

## Features

- PIC shellcode output (raw `.bin`, `.exe`, or `.dll`)
- CS 4.13-compatible UDRL-VS (User Defined Reflective Loader) integration
- Sleepmask COFF support (XOR heap masking, Ekko timer-queue ROP)
- Beacon Gate: routes Win32 API calls through the sleepmask COFF for CFG compatibility
- BOF (Beacon Object File) execution engine with full `beacon.h` API
- Four injection techniques: CRT, Early Bird APC, NtCreateSection, Custom (plus HellsHall direct-syscall dispatch)
- HellsHall indirect syscalls (x64/x86): SSN extraction from ntdll, hooked-stub recovery, random `syscall` instruction gadget
- Callstack spoofing (x64, SilentMoonwalk/desync): WMI, RPC, or custom-module frame chains routed through every syscall
- Module stomping (x64): agent code copied into a signed DLL's `.text` so all return addresses are file-backed
- Module shifting (x64): backup/restore of the sacrifice region on exit (erases the Modified-Code IoC), pad offset to keep the section's first page matching disk, and transient shift-and-restore execution for EA/BOF bootstraps with zero residual artifacts
- Fork-and-run for BOF and execute-assembly (sacrifice process via APC, CFG-safe)
- AMSI and ETW patching at agent init and in every CLR bootstrap path
- Smart inject (RW to RX split permissions), PE header stomping, section obfuscation
- Binary TLV wire protocol with AES-256-CBC encryption
- Compile-time command selection (only ship what you need)

## Agent Internals

The agent is a single `INSTANCE` struct allocated in PIC memory. It holds all resolved API function pointers, transport state, crypto keys, and beacon metadata. All Win32 calls go through the INSTANCE rather than the IAT.

**API resolution** uses DJB2 hashing to walk the PEB loader data and resolve exports by hash at runtime. No import table exists in the final shellcode.

**Wire protocol**: binary TLV (Type-Length-Value). Each message is a sequence of TLV fields (1-byte type, 4-byte big-endian length, payload). The outer layer is AES-256-CBC encrypted with Mythic's standard key exchange. The translation container converts between this binary format and Mythic's JSON tasking protocol.

**Build flow**:
1. Builder stamps `config.h` with the selected C2 profile, encryption key, commands, and evasion settings
2. `make x64` compiles all source with Clang targeting mingw-w64, links with a custom linker script that places `.text` first
3. `objcopy --dump-section .text=emeraldstrike.x64.bin` extracts the PIC shellcode
4. For UDRL mode: agent compiles as a DLL instead, the builder compiles the uploaded loader and sleepmask kits, then concatenates `loader.bin + agent.dll + padding + egg`

## Installation

1. Install [Mythic](https://github.com/its-a-feature/Mythic) on your teamserver.

2. Install the agent:
```bash
mythic-cli install github https://github.com/Whispergate/EmeraldStrike
```

3. Or run the container locally and point it at your Mythic server via `rabbitmq_config.json`:
```json
{
  "rabbitmq_host": "YOUR_MYTHIC_HOST",
  "rabbitmq_password": "YOUR_RABBITMQ_PASSWORD",
  "mythic_server_host": "YOUR_MYTHIC_HOST",
  "mythic_server_grpc_port": 17444,
  "mythic_server_port": 17443
}
```

4. Rebuild and start the container:
```bash
docker build -t emeraldstrike Payload_Type/emeraldstrike/
docker run -d --name emeraldstrike emeraldstrike
```

## C2 Profiles

| Profile | Library | Description |
|---------|---------|-------------|
| HTTP | WinINet (default) or WinHTTP | Standard HTTP/HTTPS callbacks. Configurable host, port, URIs, user-agent, proxy with auth. |
| SMB | Named Pipes | Peer-to-peer linking over named pipes. Used for internal pivoting with `link` / `unlink`. |
| Azure Blob | WinINet or WinHTTP (REST, no Azure SDK) | Polling transport over Azure Blob Storage. Blends into allowed `*.blob.core.windows.net` egress. |

### Azure Blob transport

Uses the `azure_blob` C2 profile with per-agent container isolation. At payload build time the profile creates a dedicated container (`agent-{uuid12}`) and mints a container-scoped SAS token - the storage account key never leaves the server, and a compromised agent can only touch its own container. SAS expiry ties to the payload kill date.

The agent speaks plain HTTPS REST against `https://{account}.blob.core.windows.net/{container}/`:

- `PUT  ats/{message-id}.blob` - submit a message (agent-to-server)
- `GET  sta/{message-id}.blob` - poll for the reply (server-to-agent), then `DELETE` it

Message IDs are fresh v4 GUIDs per request. The wire format (base64 of `uuid36 + payload`) is identical to the HTTP profile, so the encryption and tasking layers are unchanged. The response poll runs through the sleep mask, so Ekko-style obfuscation covers the waiting period. Trade-off: polling-based, so latency per task is roughly one C2 interval and bulk traffic (SOCKS, large downloads) is slow.

Requires the `azure_blob` C2 profile to be installed and running on the Mythic server (with its `config.json` holding the storage account credentials). Builds fail fast at provisioning time if the profile is unreachable.

### Sleep Masking

Four built-in modes, selected at compile time:

- **none**: plain `Sleep()`, no memory protection.
- **default**: XOR-masks heap records and sensitive fields during sleep, unmasks on wake.
- **ekko**: timer-queue ROP chain using `SystemFunction032` for encrypt/decrypt (x64 only). Encrypts the whole image, not just heap records.
- **udrl**: sleepmask compiled from the uploaded UDRL kit (see below).

When using UDRL-VS mode, the sleepmask is compiled from the uploaded kit as a COFF object and embedded into the agent. The agent calls into the COFF sleepmask via the `sleep_mask(PBEACON_INFO, PFUNCTION_CALL)` interface.

### Beacon Gate

When enabled (UDRL mode only), Beacon Gate routes Win32 API calls through the sleepmask COFF's gate functions. This provides CFG (Control Flow Guard) compatibility because calls originate from a valid call site within the sleepmask rather than directly from beacon memory.

Gated APIs include `VirtualAlloc`, `VirtualAllocEx`, `VirtualProtect`, `VirtualProtectEx`, `VirtualFree`, `VirtualFreeEx`, `VirtualQuery`, `VirtualQueryEx`, `CreateThread`, `CreateRemoteThread`, `OpenProcess`, `OpenThread`, `CloseHandle`, `GetThreadContext`, `SetThreadContext`, `ResumeThread`, `CreateFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile`, `DuplicateHandle`, `ReadProcessMemory`, `WriteProcessMemory`, `WaitForSingleObject`, `Sleep`, and `ExitThread`.

### Injection Techniques

Four compile-time injection strategies for `inject` and `spawn`:

| Technique | Method |
|-----------|--------|
| CRT | `VirtualAllocEx` then `WriteProcessMemory` then `VirtualProtectEx` then `CreateRemoteThread` |
| APC | Same allocation path, then `CreateRemoteThread` (suspended) then `QueueUserAPC` then `ResumeThread` |
| Section | `NtCreateSection` then `NtMapViewOfSection` (local RW) then memcpy then `NtMapViewOfSection` (remote RX) then `CreateRemoteThread` |
| Custom | Same layout as CRT, intended as a starting point for operator-defined techniques |

Smart inject (on by default) uses RW then RX split permissions instead of RWX.

### AMSI / ETW

Patched at agent init when enabled. Each can be toggled independently via build parameters. Both patches are also applied inside every CLR bootstrap path (inline and fork-and-run execute-assembly, powerpick), since a fresh CLR loads its own copies of the relevant state.

### HellsHall indirect syscalls

Enabled with `indirect_syscalls`. At init the agent walks ntdll's export directory, extracts SSNs from the `mov eax, SSN` stub pattern, and recovers SSNs for hooked stubs from their unhooked neighbours. Syscall dispatch jumps to a `syscall; ret` instruction found at a random offset inside ntdll (or `sysenter`/`int 0x2e` on x86), so the return address never points at the agent. Hashes are computed at runtime from obfuscated strings - no static hash table exists in the payload.

### Callstack spoofing

`callstack_spoof` (x64, standalone PIC builds only - hidden and force-disabled under UDRL). Wraps every HellsHall syscall dispatch in a SilentMoonwalk-style ROP chain: four fabricated frames built from real `KernelBase.dll` unwind entries, so the stack walker sees the syscall returning into a legitimate module instead of the agent's memory. Frame sources per mode:

- `wmi` - `wbemcomn.dll` / `fastprox.dll` (WMI provider callback chain)
- `rpc` - `rpcrt4.dll` (RPC dispatch chain)
- `custom` - operator-specified module (`callstack_spoof_module`)

Gadget discovery scans the module's `.pdata` at init; if the spoofer fails to initialize, every syscall silently falls back to direct dispatch.

### Module stomping

`module_stomp` (x64, standalone PIC builds only - hidden and force-disabled under UDRL). At init the agent loads a sacrificial signed DLL (`HostNetSvc.dll`, `WsmSvc.dll`, `localspl.dll`, or `gpsvc.dll` - picked at random from whichever exists) via a VEH-intercepted `LoadLibraryW` that neuters its `DllMain` and skips TLS init, then copies its own code into the DLL's `.text` section and transfers execution there. The original allocation is zeroed and freed. Result: every return address in every call stack - including transport calls that never touch a syscall - resolves into a file-backed, Microsoft-signed module. Verified with a `VirtualQueryEx` sweep: zero `MEM_PRIVATE` executable regions after stomp.

### Module shifting

`module_shift` (x64, standalone PIC builds only - hidden and force-disabled under UDRL, implies `module_stomp`). Implements naksyn's ModuleShifting refinement of module stomping: the sacrifice region is backed up before the overwrite and restored when the agent exits, erasing the Modified-Code IoC that memory-vs-disk differencing tools (Moneta, PE-Sieve) key on. The agent blob also lands at `section_base + 0x200` (the `module_shift_pad` toggle, on by default) so the section's first page still matches the on-disk image - mimicking the benign partial-overwrite look of a legitimate page-in. The relationship to the other modes:

- `module_stomp` - persistent file-backed execution, agent bytes remain in the sacrifice `.text` for the agent's lifetime
- `module_shift` - the same stomp, plus backup/restore of the original `.text`/`.pdata` bytes on exit and the pad offset
- `shift_bootstrap` - transient write-execute-restore: `execute_assembly`/`inline_execute` fork-and-run bootstraps run inside a shifted DLL section **in-process** (no sacrifice process at all), and the original section bytes are restored the moment the bootstrap returns - zero residual artifacts per run

Because the agent is executing inside the region it wants to restore, the persistent-stomp exit restore cannot memcpy back in place. A small position-independent restore stub (`rep movsb` + `VirtualProtect` + exit handoff) is staged in a freshly allocated page and does the copy from memory that is not part of the restored region, then transfers directly to `ExitThread`/`ExitProcess` per the `exit` method. The transient `shift_bootstrap` path restores inline - it executes from the agent's own allocation, not the shifted region.

### Fork-and-run

`execute_assembly`, `inline_execute`, and `powerpick` can run in a sacrificial process instead of inline. The sacrifice is spawned suspended and the bootstrap is queued via APC.

## UDRL-VS Integration

EmeraldStrike supports Cobalt Strike 4.13-compatible User Defined Reflective Loaders. Upload the UDRL kit as a ZIP file containing `loader/` and `mask/` directories, each with their own Makefile.

The build process:
1. Compiles the sleepmask COFF from `mask/` and embeds it in the agent's `config.h` as a byte array
2. Compiles the agent as a proper PE DLL (with relocations preserved, entry point at `DllMain`)
3. Builds the loader PIC shellcode from `loader/`
4. Concatenates: `loader.bin + agent.dll + padding + egg marker`, page-aligned

The loader handles reflective loading: allocating memory, mapping sections, resolving the IAT, processing relocations, and calling `DllMain` with `DLL_BEACON_USER_DATA` (0x0d) to pass the `USER_DATA` struct, then `DLL_PROCESS_ATTACH` (0x01) and `DLL_BEACON_START` (0x04) to start the agent loop.

## BOF Support

The COFF loader (`coff_loader.cc`) implements a full Beacon Object File execution engine:

- Parses COFF file headers, section headers, symbols, and relocations
- Supports AMD64 relocation types (`ADDR64`, `ADDR32NB`, `REL32` and its variants) and i386 types (`DIR32`, `DIR32NB`, `REL32`)
- Resolves external symbols against the beacon API function table
- Locates and calls the `go` entry point with argument data
- Collects output from `BeaconOutput` / `BeaconPrintf` calls

The full `beacon.h` API surface is implemented: data parsing (`BeaconDataParse`, `BeaconDataInt`, `BeaconDataExtract`), format building (`BeaconFormatAlloc`, `BeaconFormatAppend`, `BeaconFormatInt`), output (`BeaconOutput`, `BeaconPrintf`), token operations (`BeaconUseToken`, `BeaconRevertToken`), spawn+inject (`BeaconSpawnTemporaryProcess`, `BeaconInjectProcess`), information (`BeaconInformation`, `BeaconGetCustomUserData`), key/value store (`BeaconAddValue`, `BeaconGetValue`, `BeaconRemoveValue`), data store, and gate control (`BeaconDisableBeaconGate`, `BeaconEnableBeaconGate`).

Register BOFs for repeated use with `register_bof`, then execute with `inline_execute`.

## CS 4.13 Compatibility

EmeraldStrike matches Cobalt Strike 4.13 structures and interfaces:

- `beacon.h`: `datap`, `formatp`, `BEACON_INFO`, `USER_DATA`, `ALLOCATED_MEMORY`, `DATA_STORE_OBJECT`, `SYSCALL_API`, all callback constants
- `beacon_gate.h`: `FUNCTION_CALL` struct, `WinApi` enum, `BEACON_GATE_XX` function pointer typedefs
- `DllMain` protocol: handles `DLL_BEACON_USER_DATA` (0x0d) and `DLL_BEACON_START` (0x04)
- Version: `0x041300`

Existing CS 4.13 UDRL kits, sleepmask kits, and BOFs work with little to no modification.

## Customization

### Adding a command

1. Create `agent_code/src/commands/cmd_mycommand.cc`, gate it with `#ifdef INCLUDE_CMD_MYCOMMAND`
2. Add `#define INCLUDE_CMD_MYCOMMAND` to `config.h`
3. Register it in the dispatch table (`dispatch.cc`)
4. Create `Payload_Type/.../agent_functions/mycommand.py` with the Mythic command definition
5. Add the parameter schema to `translator.py` in `_CMD_SCHEMAS`

### Adding an injection technique

1. Add a new `#elif INJECTION_TECHNIQUE == INJECT_YOURMETHOD` block in `injection.cc`
2. Add the constant to `config.h`
3. Add the choice to `injection_technique` in `builder.py`

### Adding a transport

1. Create `agent_code/src/transport/mytransport.cc` implementing the same surface as `http.cc` (the `send_mythic_msg` path in `main.cc` needs a send function; the wire format should stay `base64(uuid36 + payload)`)
2. Add a `#ifdef MY_TRANSPORT` parse branch to `parse_config` in `main.cc` and a config struct to `INSTANCE` in `include/common.h`
3. Wire the transport into `agent_init` (API/library resolution) and the `agent_main` loop gates
4. In `builder.py`: add the profile name to `c2_profiles`, stamp the define, serialize the new config fields in `_serialize_config` (mirroring the parse order exactly), and provision any server-side resources before stamping

## Testing

`tests/` contains pytest suites covering the builder, linker/layout invariants, and each evasion feature:

```bash
python -m pytest tests/ -q
```

Compile-verification for manual changes (expands `config.h` inside the container - restore it from the host afterward; the container has no `.git`):

```bash
docker run --rm -v "<agent_code>:/agent_code" emeraldstrike:latest bash -c "cd /agent_code && mkdir -p bin/obj && make x64"
```

Key invariants the tests enforce: the six `config.h` placeholders exist (a clobbered template still compiles but produces an agent that never calls back), `__InstanceStorage` sorts last in the linker script, and callstack spoofing / module stomping are force-disabled under UDRL.

## Known Limitations

- Module stomping and callstack spoofing are x64-only and unavailable under UDRL-VS builds (the loader kit controls memory layout there).
- Module shifting restores the sacrifice region only at agent exit; while the agent is alive, the stomped `.text` still differs from disk (though the padded first page matches). The transient `shift_bootstrap` path restores after every run.
- The module-stomp transplant does not yet rebase the agent's `.pdata` unwind entries - the stomped region keeps the sacrifice DLL's original unwind info, so stack walks through stomped frames are clean but shallow (all shown frames are file-backed).
- Ekko sleep masking is x64-only; x86 builds fall back to the default XOR mask.
- Azure Blob transport is polling-based: per-task latency is roughly one C2 interval, and high-volume channels (SOCKS, large transfers) are slow.
- Fork-and-run `powerpick` uses a unique-per-task PSRunner assembly; the first run in a fresh sacrifice pays PowerShell runspace startup cost.
