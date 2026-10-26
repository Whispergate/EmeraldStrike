+++
title = "detection_surface"
chapter = false
weight = 10
+++

## Detection Surface Analysis

### Process-Level Indicators

| Indicator | Detail | Mitigation |
|-----------|--------|------------|
| Sacrifice process creation | `spawn` creates a suspended process (default: `rundll32.exe`) | Change spawnto to a less suspicious binary via `spawnto_x64` / `spawnto_x86` |
| `cmd.exe` child process | `shell` spawns `cmd.exe /c` as a child | Use BOFs via `inline_execute` for stealthier alternatives |
| Cross-process injection | `inject` / `spawn` use `OpenProcess(PROCESS_ALL_ACCESS)` | Section-based injection (`INJECT_SECTION`) reduces API telemetry |
| Process listing | `ps` uses `CreateToolhelp32Snapshot` | Standard API - low detection risk |
| Process termination | `kill` calls `TerminateProcess` | May alert EDR if targeting security processes |

### Network Indicators

| Indicator | Detail | Mitigation |
|-----------|--------|------------|
| HTTP beacon pattern | Regular GET/POST intervals with base64 in query parameter | Configure jitter to randomize intervals |
| WinInet User-Agent | Default User-Agent may not match environment | Set User-Agent to match target browsers in C2 profile |
| Self-signed TLS | `SECURITY_FLAG_IGNORE_ALL` accepts any certificate | Use valid certificates on redirectors |
| Beaconing cadence | Fixed interval with jitter is still periodic | Use longer sleep intervals with higher jitter |

### Memory Indicators

| Indicator | Detail | Mitigation |
|-----------|--------|------------|
| RWX memory regions | CRT and APC injection leave `PAGE_EXECUTE_READWRITE` in target | Use section-based injection for RX remote mapping |
| PIC shellcode in memory | Agent code resides in a single allocated memory region | Enable sleep masking (Ekko or UDRL) to encrypt during sleep |
| Function pointer table | `inst->Win32` contains resolved API addresses | Beacon Gate routes calls through sleepmask context |
| Unencrypted strings | Config data (UUID, host, URIs) in instance struct | Sleep mask XOR/encrypt during sleep cycles |

### ETW and Event Log Coverage

| Source | Event | Triggered By |
|--------|-------|-------------|
| Sysmon Event ID 1 | Process creation | `shell`, `spawn` |
| Sysmon Event ID 8 | CreateRemoteThread | `inject`, `spawn` (CRT/Section techniques) |
| Sysmon Event ID 10 | Process access | `inject`, `spawn`, `kill` |
| Sysmon Event ID 23/26 | File deletion | `rm` |
| Security Event 4688 | Process creation with command line | `shell` |

### Recommendations

1. **Change the spawnto binary** from `rundll32.exe` to a less suspicious process (`RuntimeBroker.exe`, `dllhost.exe`) before using `spawn`.
2. **Use BOFs** via `inline_execute` instead of `shell` for discovery and enumeration tasks.
3. **Enable sleep masking** (Ekko or UDRL mode) to encrypt agent memory during sleep cycles.
4. **Use section-based injection** (`INJECT_SECTION`) to eliminate `VirtualAllocEx`/`WriteProcessMemory` telemetry.
5. **Configure realistic C2 parameters** - match User-Agent to the target environment, use HTTPS with valid certificates, and set appropriate sleep/jitter values.
6. **Enable Beacon Gate** with a UDRL sleepmask for call stack spoofing and indirect syscall support.
