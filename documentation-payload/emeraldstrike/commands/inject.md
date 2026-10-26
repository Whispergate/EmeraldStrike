+++
title = "inject"
chapter = false
weight = 103
+++

## Summary

Inject shellcode into a remote process by PID.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| pid | Number | Yes | - | Target process ID to inject into |
| shellcode_file | File | Yes | - | Shellcode file to inject |

### Usage

```
inject -PID 1234 -Shellcode <shellcode.bin>
```

## Detailed Summary

The Python tasking handler fetches shellcode content from Mythic via `SendMythicRPCFileGetContent`, base64-encodes it, and sends it to the agent.

On the agent side:

1. Parses the PID and shellcode bytes from the task parameters.
2. Opens the target process with `OpenProcess` using `PROCESS_ALL_ACCESS`.
3. Injects the shellcode using the compile-time selected injection technique.
4. Closes all handles.

### Available Injection Techniques

| Technique | Build Value | Method |
|-----------|------------|--------|
| **CreateRemoteThread** (default) | `crt` | `VirtualAllocEx(RW)` -> `WriteProcessMemory` -> `VirtualProtectEx(RWX)` -> `CreateRemoteThread` |
| **APC Early Bird** | `apc` | Same alloc/write/protect + suspended `SleepEx` thread + `QueueUserAPC` + `ResumeThread` |
| **NtCreateSection** | `section` | `NtCreateSection` -> `NtMapViewOfSection` (local RW) -> copy -> `NtMapViewOfSection` (remote RX) -> `CreateRemoteThread` |
| **Custom** | `custom` | Operator-defined (defaults to CRT implementation) |

### APIs Used (CRT - default)

| API | Purpose |
|-----|---------|
| `OpenProcess` | Open target process with PROCESS_ALL_ACCESS |
| `VirtualAllocEx` | Allocate RW memory in target |
| `WriteProcessMemory` | Write shellcode to allocated memory |
| `VirtualProtectEx` | Change memory protection to RWX |
| `CreateRemoteThread` | Execute shellcode in target |
| `CloseHandle` | Clean up handles |

## MITRE ATT&CK Mapping

- **T1055.001** - Process Injection: Dynamic-link Library Injection

## OPSEC Considerations

{{% notice warning %}}
Process injection is a heavily monitored activity. The CRT technique generates `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` cross-process telemetry (Sysmon Event ID 8). Requesting `PROCESS_ALL_ACCESS` is aggressive and may trigger alerts. Consider the section-based technique for reduced API telemetry.
{{% /notice %}}

- **CRT**: Cross-process `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` is heavily monitored
- **APC**: No `CreateRemoteThread` event but `QueueUserAPC` cross-process is monitored by some EDRs
- **Section**: No `VirtualAllocEx`/`WriteProcessMemory` telemetry - shared section blends with legitimate memory
- **Custom**: Detection surface depends on implementation
- Target process selection matters - injecting into system processes requires elevation
