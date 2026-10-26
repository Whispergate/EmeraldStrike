+++
title = "steal_token"
chapter = false
weight = 103
+++

## Summary

Steal an access token from a target process and impersonate it for subsequent tasks.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| pid | Number | Yes | - | Process ID to steal the token from |

### Usage

```
steal_token -pid 1234
steal_token -pid 612
```

## Detailed Summary

Opens the target process, duplicates its primary token, and applies it to the beacon's thread for impersonation. All subsequent commands run under the stolen token's security context until `rev2self` is called.

1. Opens the target process with `OpenProcess` (PROCESS_QUERY_INFORMATION).
2. Opens the process token with `OpenProcessToken` (TOKEN_DUPLICATE | TOKEN_QUERY).
3. Duplicates the token with `DuplicateTokenEx` as an impersonation token.
4. Applies the token to the current thread with `ImpersonateLoggedOnUser` or `SetThreadToken`.
5. Stores the token handle for later cleanup by `rev2self`.

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenProcess` | Open target process |
| `OpenProcessToken` | Get process token handle |
| `DuplicateTokenEx` | Duplicate as impersonation token |
| `ImpersonateLoggedOnUser` | Apply token to current thread |

## MITRE ATT&CK Mapping

- **T1134.001** - Access Token Manipulation: Token Impersonation/Theft

## OPSEC Considerations

{{% notice warning %}}
Token theft requires opening a handle to the target process and its token. This generates cross-process handle events visible to EDR. Stealing tokens from protected processes (like lsass.exe) requires SeDebugPrivilege and is heavily monitored.
{{% /notice %}}

- Cross-process handle open is logged by Sysmon Event ID 10
- Requires appropriate privileges to open the target process
- The stolen token persists until `rev2self` is called

## Limitations

- Cannot steal tokens from processes running at a higher integrity level without SeDebugPrivilege.
- The impersonation applies to network logon type -- local file access still uses the beacon's original token unless the token is a primary token.
