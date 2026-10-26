+++
title = "getprivs"
chapter = false
weight = 103
+++

## Summary

Enable all available privileges in the current access token and list them.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

None.

### Usage

```
getprivs
```

## Detailed Summary

Enumerates all privileges in the current process token and attempts to enable each one using `AdjustTokenPrivileges`. Returns a table of all privileges with their current state (enabled/disabled).

1. Opens the current process token with `TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY`.
2. Calls `GetTokenInformation` with `TokenPrivileges` to enumerate all privileges.
3. Resolves each privilege LUID to its name via `LookupPrivilegeNameA`.
4. Attempts to enable each privilege with `AdjustTokenPrivileges`.
5. Returns a formatted table of privilege names and their status.

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenProcessToken` | Get current process token |
| `GetTokenInformation` | Enumerate token privileges |
| `LookupPrivilegeNameA` | Resolve LUID to privilege name |
| `AdjustTokenPrivileges` | Enable privileges |

## MITRE ATT&CK Mapping

- **T1134.002** - Access Token Manipulation: Create Process with Token

## OPSEC Considerations

{{% notice info %}}
Enabling privileges like `SeDebugPrivilege` may trigger alerts in environments that monitor privilege escalation. The operation itself only adjusts the current token -- no new processes are created.
{{% /notice %}}

## Limitations

- Can only enable privileges that are already present in the token. Cannot add new privileges.
- Some privileges (like `SeDebugPrivilege`) require the token to already hold them, typically requiring an elevated (admin) context.
