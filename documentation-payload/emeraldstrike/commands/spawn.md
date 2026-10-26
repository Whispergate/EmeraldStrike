+++
title = "spawn"
chapter = false
weight = 103
+++

## Summary

Inject shellcode into a new sacrifice process or an existing process by PID.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| template | Payload | Yes | - | Payload template to generate shellcode from (must be emeraldstrike with output_type=bin) |
| pid | Number | No | 0 | Process ID to inject into. Leave as 0 to spawn a new sacrifice process using the spawnto path. |

### Usage

```
spawn -Payload <template>
spawn -Payload <template> -PID 1234
```

## Detailed Summary

The `spawn` command injects generated shellcode into either a newly spawned sacrifice process or an existing process specified by PID. A new payload instance is generated from the selected Mythic payload template before injection.

The Python tasking handler validates the selected payload template: it must have a successful build phase, and the output must be raw shellcode (not a PE - an `MZ` header check rejects DLL/EXE payloads). The shellcode is base64-encoded and sent to the agent.

**When PID is 0 (default - spawn new process):**

1. Reads the configured `spawnto_x64` path and arguments from the agent instance.
2. Converts the spawnto path and arguments to a wide-character command line via `MultiByteToWideChar`.
3. Creates a new suspended, hidden process via `CreateProcessW` with `CREATE_SUSPENDED | CREATE_NO_WINDOW` flags and `SW_HIDE`.
4. Injects the shellcode into the new process using the configured injection technique (via `inject_shellcode_into`).
5. If injection fails, terminates the spawned process with `TerminateProcess` and cleans up handles.
6. If injection succeeds, closes all handles. The injected thread runs independently - the sacrifice process's main thread remains suspended.

**When PID is specified (inject into existing):**

1. Opens the target process with `PROCESS_ALL_ACCESS` via `OpenProcess`.
2. Injects the shellcode using the configured injection technique.

### APIs Used

| API | Purpose |
|-----|---------|
| `MultiByteToWideChar` | Convert spawnto path to wide string |
| `CreateProcessW` | Spawn a new suspended sacrifice process |
| `inject_shellcode_into` | Inject shellcode using the configured technique |
| `inject_shellcode` | Open process and inject (PID mode) |
| `TerminateProcess` | Kill the sacrifice process if injection fails |
| `CloseHandle` | Clean up process and thread handles |

## MITRE ATT&CK Mapping

- **T1055.001** - Process Injection: Dynamic-link Library Injection
- **T1055.012** - Process Injection: Process Hollowing

## OPSEC Considerations

{{% notice warning %}}
This command performs process injection, which is a heavily monitored activity. Creating a suspended process and injecting into it is a well-known pattern detected by most EDR solutions. When injecting into an existing process by PID, requesting `PROCESS_ALL_ACCESS` is aggressive and may trigger alerts. The default spawnto binary (`rundll32.exe`) is commonly flagged - consider changing it via `spawnto_x64` or `spawnto_x86` to a less suspicious binary before using this command.
{{% /notice %}}
