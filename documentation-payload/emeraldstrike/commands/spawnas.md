+++
title = "spawnas"
chapter = false
weight = 103
+++

## Summary

Spawn a new beacon as a different user using the specified credentials. Creates a process with the provided credentials and injects shellcode into it.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| Payload | Payload | Yes | - | Payload template to generate shellcode from (must be emeraldstrike with output_type=bin) |
| domain | String | Yes | - | Domain (use `.` for local) |
| username | String | Yes | - | Username |
| password | String | Yes | - | Password |

### Usage

```
spawnas -Payload <template> -domain CORP -username admin -password P@ssw0rd
```

## Detailed Summary

The Python tasking handler generates a new payload from the selected template, validates it built successfully and is raw shellcode (not a PE), then base64-encodes it for the agent.

On the agent side:

1. Calls `CreateProcessWithLogonW` with the provided credentials and the configured `spawnto_x64` path, creating a suspended, hidden process.
2. Injects the shellcode into the new process using the configured injection technique (via `inject_shellcode_into`).
3. If injection fails, terminates the spawned process and cleans up handles.
4. The injected code runs in the new process under the specified user's context.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateProcessWithLogonW` | Create process with alternate credentials |
| `inject_shellcode_into` | Inject shellcode using configured technique |
| `TerminateProcess` | Kill child process on injection failure |
| `CloseHandle` | Clean up handles |

## MITRE ATT&CK Mapping

- **T1134.002** - Access Token Manipulation: Create Process with Token

## OPSEC Considerations

{{% notice warning %}}
This command creates a new process with explicit credentials, generating a logon event (Event ID 4624, logon type 2 or 9) and process creation event. The process injection into the new child is also observable. The default spawnto binary (`rundll32.exe`) is commonly flagged -- change it via `spawnto_x64` before use.
{{% /notice %}}

## Limitations

- The payload template must produce raw shellcode (`output_type=bin`), not a PE.
- The spawnto path must be set to a valid executable.
