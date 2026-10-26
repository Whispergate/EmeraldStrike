+++
title = "runu"
chapter = false
weight = 103
+++

## Summary

Run a command as a different user using `CreateProcessWithLogonW`. The command runs with the specified credentials and output is captured.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| domain | String | Yes | - | Domain (use `.` for local) |
| username | String | Yes | - | Username |
| password | String | Yes | - | Password |
| command | String | Yes | - | Command to execute |

### Usage

```
runu -domain CORP -username admin -password P@ssw0rd -command "whoami /all"
runu -domain . -username localadmin -password Pass123 -command "net user"
```

## Detailed Summary

Creates a process under alternate credentials using `CreateProcessWithLogonW`. Output is captured via anonymous pipes, similar to `run`.

1. Calls `CreateProcessWithLogonW` with the provided domain, username, password, and command.
2. Captures stdout/stderr via pipe redirection.
3. Returns the output to the operator.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateProcessWithLogonW` | Create process with alternate credentials |
| `CreatePipe` | Output capture |
| `ReadFile` | Read process output |

## MITRE ATT&CK Mapping

- **T1134.002** - Access Token Manipulation: Create Process with Token

## OPSEC Considerations

{{% notice warning %}}
Generates a logon event (Event ID 4624) and process creation event with the specified credentials. The credential material is passed to the API in cleartext.
{{% /notice %}}
