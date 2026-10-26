+++
title = "getuid"
chapter = false
weight = 307
+++

## Summary

Get the current user identity in `DOMAIN\username` format via process token query.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
getuid
```

**Example Output:**

```
CORP\jsmith
```

## Detailed Summary

Opens the current process token with `OpenProcessToken` and queries it using `GetTokenInformation` with the `TokenUser` information class. The SID is resolved to a `DOMAIN\username` string via `LookupAccountSidA`.

Functionally equivalent to `whoami` - both commands return the current user identity from the process token.

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenProcessToken` | Open the current process token |
| `GetTokenInformation` | Retrieve token user SID |
| `LookupAccountSidA` | Resolve SID to domain and username |
| `CloseHandle` | Close token handle |

## MITRE ATT&CK Mapping

- **T1033** - System Owner/User Discovery
