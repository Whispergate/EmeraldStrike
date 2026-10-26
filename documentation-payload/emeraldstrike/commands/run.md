+++
title = "run"
chapter = false
weight = 103
+++

## Summary

Execute a program directly (without `cmd.exe`) and capture its output. Unlike `shell`, this does not invoke a command interpreter.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| executable | String | Yes | - | Path to executable |
| arguments | String | No | "" | Arguments to pass |

### Usage

```
run net user /domain
run C:\Windows\System32\ipconfig.exe /all
run whoami.exe /priv
```

## Detailed Summary

Creates the specified process directly using `CreateProcessA` with pipe-based stdout/stderr capture. The process runs hidden (`SW_HIDE`, `CREATE_NO_WINDOW`).

1. Creates an anonymous pipe for stdout/stderr capture.
2. Calls `CreateProcessA` with the executable and arguments as the command line.
3. Waits for the process to complete.
4. Reads all output from the pipe and returns it.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreatePipe` | Create anonymous pipe for output capture |
| `CreateProcessA` | Spawn the executable directly |
| `ReadFile` | Read from pipe handle |
| `WaitForSingleObject` | Wait for process completion |
| `CloseHandle` | Clean up handles |

## MITRE ATT&CK Mapping

- **T1106** - Native API

## OPSEC Considerations

{{% notice info %}}
Unlike `shell`, this command does not create a `cmd.exe` child process, making it slightly less conspicuous. However, the spawned process is still visible in process listings and its parent-child relationship with the beacon's host process is observable.
{{% /notice %}}

- No `cmd.exe` intermediary -- the executable runs as a direct child
- Process creation is logged by Sysmon Event ID 1 and Security Event 4688
- Use `execute` instead if output capture is not needed
