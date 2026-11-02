+++
title = "OPSEC"
chapter = true
weight = 20
+++

# OPSEC Considerations

Operational security guidance for deploying and operating EmeraldStrike. The sub-pages cover [evasion features]({{% relref "/agents/emeraldstrike/opsec/evasion" %}}), [detection surface analysis]({{% relref "/agents/emeraldstrike/opsec/detection_surface" %}}), and [UDRL development]({{% relref "/agents/emeraldstrike/opsec/udrl_development" %}}) in detail. This page provides a deployment checklist and general guidance.

---

## Pre-Deployment Checklist

Run through this before generating a payload for an engagement.

### Build Configuration

| Setting | Recommended | Why |
|---------|-------------|-----|
| `output_type` | `bin` with UDRL-VS | Raw shellcode loaded by reflective loader avoids PE on disk |
| `loader_type` | `udrl-vs` | Module stomping, sleepmask COFF, Beacon Gate, callstack spoofing |
| `sleep_mask` | `ekko` (standalone) or UDRL kit mask | Encrypts agent memory during sleep; Ekko uses timer-queue ROP so the mask code itself is not on the call stack |
| `injection_technique` | `section` | NtCreateSection avoids `VirtualAllocEx`/`WriteProcessMemory` telemetry |
| `smartinject` | `true` | RW then RX split; no RWX regions in the target process |
| `userwx` | `false` | Avoids RWX in the agent's own allocations |
| `stomppe` | `true` | Zeros PE headers after load; removes MZ/PE signatures from memory |
| `obfuscate` | `true` | XOR non-executable sections on load; reduces static signatures in memory |
| `cleanup` | `true` | Frees the initial shellcode allocation (standalone mode only; UDRL handles its own cleanup) |
| `patch_amsi` | `true` | Required for `execute_assembly` and `powerpick` to run without AMSI scanning |
| `patch_etw` | `true` | Suppresses .NET and script block ETW events |
| `beacon_gate` | `true` | Routes API calls through sleepmask for CFG compatibility and call stack spoofing (UDRL only) |
| `debug` | `false` | Debug builds emit `OutputDebugStringA` messages visible to DebugView or an attached debugger |

### Spawnto Configuration

The default spawnto binary (`rundll32.exe`) is heavily monitored by EDR. Change it before using `spawn`, `execute_assembly`, or `powerpick`:

```
spawnto_x64 C:\Windows\System32\RuntimeBroker.exe
spawnto_x86 C:\Windows\SysWOW64\RuntimeBroker.exe
```

Other reasonable choices: `dllhost.exe`, `SearchProtocolHost.exe`, `backgroundTaskHost.exe`. Pick a binary that normally runs on the target and does not stand out in process trees.

---

## Operational Guidance

### Prefer BOFs Over Shell Commands

`shell` spawns `cmd.exe /c` as a child process, generating Sysmon Event ID 1 and Security Event 4688 with full command-line logging. For discovery and enumeration, use `inline_execute` with BOFs instead:

- Directory listing: BOF instead of `shell dir`
- Network enumeration: BOF instead of `shell net view`
- Registry queries: BOF instead of `shell reg query`

The BOF runs inside the agent's process (or the spawnto process for fork-and-run BOFs) and does not create a `cmd.exe` child.

### Injection Considerations

`inject` and `spawn` both open a handle to the target process with `PROCESS_ALL_ACCESS`. This generates Sysmon Event ID 10 (ProcessAccess).

Section-based injection (`INJECT_SECTION`) reduces the API surface: it avoids `VirtualAllocEx` and `WriteProcessMemory`, using `NtCreateSection` + `NtMapViewOfSection` instead. The remote mapping is `PAGE_EXECUTE_READ` (no write permission), and the local mapping used for copying is unmapped before the remote thread starts.

With Beacon Gate enabled, the `CreateRemoteThread` call itself is routed through the sleepmask, so the call stack points to the sleepmask's stomped module rather than the agent.

### Sleep Intervals and Memory Encryption

Longer sleep intervals reduce network visibility but increase the window during which the agent's memory is decrypted (in standalone mode with `MASK_DEFAULT`). The Ekko timer-queue mask and UDRL sleepmask COFF encrypt memory for the full sleep duration.

Setting sleep to 0 disables the sleep cycle entirely. The agent loops without pause, generating continuous network traffic. Only use `sleep 0` for time-sensitive operations and restore a normal interval afterward.

### Token Operations

`steal_token` opens a handle to the target process and duplicates its token. `make_token` creates a new logon session with `LogonUserA`. Both leave artifacts:

- `steal_token`: Sysmon Event ID 10 (ProcessAccess) on the target PID
- `make_token`: Security Event 4624 (Logon Type 9 - NewCredentials)

Use `rev2self` to drop the impersonated token when finished. Leaving a stolen token active increases the blast radius if the agent is discovered.

### File Operations

`upload` writes to disk. `download` reads from disk and sends the content over C2. Both are straightforward file I/O and will trigger file-system minifilter callbacks (EDR file monitoring, Sysmon Event ID 11/15).

For sensitive file access, consider reading files through a BOF that uses direct `NtReadFile` syscalls to reduce the EDR callback surface.

### SOCKS and Port Forwarding

`socks` and `rportfwd` create persistent network connections that remain active across sleep cycles. They generate sustained network activity that differs from the agent's normal beacon pattern. Monitor job status with `jobs` and clean up with `jobkill` when no longer needed.

### Argument Spoofing

`argue` sets a fake command line that appears in process creation events. The actual arguments are patched into the process memory after creation. This helps when the real arguments would be suspicious in logs, but note that some EDR products read arguments from process memory rather than the creation event, which would see the real values.

---

## Cleanup

Before exiting an engagement:

1. Kill all running jobs (`jobs`, then `jobkill` for each)
2. Drop any impersonated tokens (`rev2self`)
3. Reset spawnto to defaults if changed
4. Remove any uploaded files from disk
5. `exit` the agent (thread exit by default; process exit if the agent is the only thread)

The agent does not persist across reboots. If the process hosting the agent terminates, the agent is gone. Persistence must be established separately (e.g., via a BOF that installs a scheduled task or service).

---

## Sub-Pages

{{% children %}}
