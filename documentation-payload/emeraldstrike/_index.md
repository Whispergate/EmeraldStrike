+++
title = "EmeraldStrike"
chapter = true
weight = 1
+++

## Summary

EmeraldStrike is a Windows post-exploitation agent for [Mythic](https://github.com/its-a-feature/Mythic). It compiles to raw x64/x86 PIC (Position-Independent Code) shellcode that runs entirely from memory with no PE on disk. The agent is compatible with Cobalt Strike 4.13 loaders, sleepmasks, and Beacon Object Files.

### Key Capabilities

- **PIC shellcode** output (`.bin`, `.exe`, or `.dll`) cross-compiled with Clang + mingw-w64
- **UDRL-VS** (User Defined Reflective Loader) integration with module stomping and callstack spoofing
- **Sleepmask COFF** support: XOR heap masking, Ekko timer-queue ROP, or uploaded sleepmask kit
- **Beacon Gate**: routes Win32 API calls through the sleepmask for CFG compatibility
- **BOF execution engine** with full `beacon.h` API (data parsing, format building, output, token ops, spawn+inject, key/value store, data store, gate control)
- **Four injection techniques**: CreateRemoteThread, Early Bird APC, NtCreateSection, Custom
- **AMSI/ETW patching**, smart inject (RW then RX), PE header stomping, section obfuscation
- **Two C2 transports**: HTTP (WinINet or WinHTTP) and SMB named pipes (P2P linking)
- **Binary TLV wire protocol** with AES-256-CBC encryption
- **40+ commands** with compile-time selection (only ship what you need)

### Supported C2 Profiles

| Profile | Description |
|---------|-------------|
| [HTTP]({{% relref "/agents/emeraldstrike/c2_profiles/http" %}}) | HTTP/HTTPS callbacks via WinINet (default) or WinHTTP. Configurable host, port, URIs, user-agent, proxy. |
| [SMB]({{% relref "/agents/emeraldstrike/c2_profiles/smb" %}}) | Peer-to-peer named pipe transport for internal pivoting with `link` / `unlink`. |

### Build Parameters

EmeraldStrike's payload builder exposes three groups of parameters:

- **Main**: output format (`bin`/`dll`/`exe`), architecture (`x64`/`x86`), debug mode, HTTP library selection
- **UDRL**: loader type (`default` or `udrl-vs`) and uploaded kit ZIP
- **Evasion**: sleep mask mode, injection technique, cleanup, PE stomping, obfuscation, RWX policy, smart inject, AMSI/ETW patching, Beacon Gate

All evasion settings are compile-time toggles. Unused commands and features are excluded from the binary.

### OPSEC

See the [OPSEC]({{% relref "/agents/emeraldstrike/opsec" %}}) section for deployment checklists, detection surface analysis, evasion feature details, and UDRL development guidance.

### Authors

- [@Lavender-exe](https://github.com/Lavender-exe)

## Documentation

{{% children %}}