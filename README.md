# EmeraldStrike

EmeraldStrike is a Windows post-exploitation agent for [Mythic](https://github.com/its-a-feature/Mythic). It compiles as position-independent code (PIC) shellcode compatible with Cobalt Strike 4.13 loaders, sleepmasks, and BOF tooling.

The agent is written in C/C++20 and cross-compiled with Clang + mingw-w64. It resolves all Win32 APIs at runtime via DJB2 hash walking the PEB, communicates over a binary TLV wire protocol with AES-256-CBC encryption, and supports HTTP (WinINet or WinHTTP) and SMB named-pipe transports.

## Features

- PIC shellcode output (raw `.bin`, `.exe`, or `.dll`)
- CS 4.13-compatible UDRL-VS (User Defined Reflective Loader) integration
- Sleepmask COFF support (XOR heap masking, Ekko timer-queue ROP)
- Beacon Gate: routes Win32 API calls through the sleepmask COFF for CFG compatibility
- BOF (Beacon Object File) execution engine with full `beacon.h` API
- Four injection techniques: CRT, Early Bird APC, NtCreateSection, Custom
- AMSI and ETW patching at agent init
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

## Build Parameters

### Main
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output_type` | Choice | `bin` | Output format: `bin` (raw PIC), `dll`, `exe` |
| `architecture` | Choice | `x64` | Target: `x64` or `x86` |
| `debug` | Boolean | `false` | Include `OutputDebugStringA` markers |
| `http_library` | Choice | `wininet` | HTTP stack: `wininet` or `winhttp` |

### UDRL
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `loader_type` | Choice | `default` | `default` (raw PIC) or `udrl-vs` (reflective loader kit) |
| `udrl_vs_file` | File | - | ZIP containing `loader/` and `mask/` with Makefiles |

### Evasion
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sleep_mask` | Choice | `default` | `none`, `default` (XOR heap), `ekko` (timer-queue ROP) |
| `injection_technique` | Choice | `crt` | `crt`, `apc` (Early Bird), `section` (NtCreateSection), `custom` |
| `cleanup` | Boolean | `true` | Free initial shellcode allocation after load |
| `stomppe` | Boolean | `true` | Zero PE headers in memory |
| `obfuscate` | Boolean | `false` | XOR non-executable sections on load |
| `userwx` | Boolean | `false` | Allow RWX memory (false = RW then RX) |
| `smartinject` | Boolean | `true` | RW then RX split permissions for injection |
| `patch_amsi` | Boolean | `true` | Patch AMSI at init |
| `patch_etw` | Boolean | `true` | Patch ETW at init |
| `beacon_gate` | Boolean | `true` | Route API calls through sleepmask (UDRL only) |

## Commands

### Filesystem
| Command | Description |
|---------|-------------|
| `shell` | Execute a command via `cmd.exe /c` |
| `run` | Execute a program directly |
| `execute` | Execute a program with output capture |
| `ls` | List directory contents |
| `cd` | Change working directory |
| `pwd` | Print working directory |
| `cat` | Read file contents |
| `cp` | Copy a file |
| `mv` | Move / rename a file |
| `rm` | Delete a file |
| `mkdir` | Create a directory |
| `upload` | Upload a file to the target |
| `download` | Download a file from the target |

### Process Management
| Command | Description |
|---------|-------------|
| `ps` | List running processes |
| `kill` | Terminate a process by PID |
| `jobs` | List running agent jobs |
| `jobkill` | Kill an agent job |

### Identity
| Command | Description |
|---------|-------------|
| `whoami` | Print current username |
| `getuid` | Get user SID and integrity level |
| `getprivs` | Enable token privileges |
| `steal_token` | Steal a token from another process |
| `make_token` | Create a token with credentials |
| `rev2self` | Drop impersonated token |

### Injection and Execution
| Command | Description |
|---------|-------------|
| `inject` | Inject shellcode into a remote process |
| `spawn` | Spawn a sacrificial process and inject shellcode |
| `spawnas` | Spawn a process as another user |
| `runu` | Run a command with a stolen token |
| `inline_execute` | Execute a Beacon Object File (BOF) |
| `register_bof` | Register a BOF for repeated use |
| `execute_assembly` | Load and run a .NET assembly in memory |
| `register_assembly` | Register a .NET assembly for repeated use |
| `powershell_import` | Import a PowerShell script |
| `powerpick` | Run PowerShell without `powershell.exe` |

### Evasion and Configuration
| Command | Description |
|---------|-------------|
| `sleep` | Set callback interval and jitter |
| `config` | View or modify runtime agent configuration |
| `spawnto_x64` | Set the default x64 spawnto program |
| `spawnto_x86` | Set the default x86 spawnto program |
| `argue` | Spoof command-line arguments |
| `ppid` | Set parent PID for spawned processes |
| `blockdlls` | Block non-Microsoft DLLs in child processes |
| `exit` | Terminate the agent |

### Networking
| Command | Description |
|---------|-------------|
| `socks` | Start or stop a SOCKS proxy |
| `rportfwd` | Reverse port forwarding |
| `link` | Link to a peer agent over SMB |
| `unlink` | Disconnect a linked agent |

## Evasion

### Sleep Masking

Three built-in modes, selected at compile time:

- **none**: plain `Sleep()`, no memory protection.
- **default**: XOR-masks heap records and sensitive fields during sleep, unmasks on wake.
- **ekko**: timer-queue ROP chain using `SystemFunction032` for encrypt/decrypt (x64 only).

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

Patched at agent init when enabled. Each can be toggled independently via build parameters.

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

Existing CS 4.13 UDRL kits, sleepmask kits, and BOFs work without modification.

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
