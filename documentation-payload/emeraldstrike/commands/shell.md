+++
title = "shell"
chapter = false
weight = 103
+++

## Summary

Execute a shell command via `cmd.exe /c` and return the combined stdout/stderr output.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **command** (String, required) - The command string to execute.

### Usage

```
shell whoami /all
```

```
shell dir C:\Users /s /b
```

```
shell net user /domain
```

## Detailed Summary

The shell command builds a command string prepended with `cmd.exe /c ` and spawns it using `CreateProcessA` with anonymous pipes for stdout and stderr capture. The command buffer is limited to 2048 bytes.

1. Creates an anonymous pipe with `CreatePipe` (inheritable handles) for stdout/stderr redirection.
2. Configures `STARTUPINFOA` with `STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW`, routing both stdout and stderr to the write end of the pipe, with `wShowWindow = SW_HIDE`.
3. Calls `CreateProcessA` with `CREATE_NO_WINDOW`.
4. Closes the write pipe handle immediately after process creation.
5. Waits for completion with `WaitForSingleObject` (30-second timeout).
6. Reads output from the read pipe in a 4096-byte loop via `ReadFile`.
7. Cleans up all handles.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreatePipe` | Create anonymous pipe for output capture |
| `CreateProcessA` | Spawn cmd.exe with redirected handles |
| `ReadFile` | Read from pipe handle |
| `WaitForSingleObject` | Wait for process completion (30s timeout) |
| `CloseHandle` | Clean up pipe and process handles |

## MITRE ATT&CK Mapping

- **T1059.003** - Command and Scripting Interpreter: Windows Command Shell

## OPSEC Considerations

{{% notice warning %}}
This command spawns `cmd.exe` as a child process, which is a well-known indicator. EDR products commonly monitor for `cmd.exe` process creation, especially from unusual parent processes. Prefer `inline_execute` with a BOF for stealthier alternatives.
{{% /notice %}}

- Creates a child `cmd.exe` process visible in process listings
- Parent-child process relationship may be flagged (e.g., shellcode host -> cmd.exe)
- Command line arguments are logged by Sysmon Event ID 1 and Windows Security Event 4688

## Limitations

- Command buffer is limited to 2048 bytes total (including `cmd.exe /c ` prefix).
- Hardcoded 30-second timeout - long-running commands will be abandoned.
