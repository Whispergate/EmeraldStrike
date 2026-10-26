+++
title = "whoami"
chapter = false
weight = 103
+++

## Summary

Get the current user identity in `DOMAIN\username` format.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
whoami
```

**Example Output:**

```
CORP\jsmith
```

## Detailed Summary

Opens the current process token with `OpenProcessToken` and queries it with `GetTokenInformation` using the `TokenUser` information class. The SID from the token user structure is resolved to a `DOMAIN\username` string via `LookupAccountSidA`.

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenProcessToken` | Open the current process token |
| `GetTokenInformation` | Retrieve token user SID |
| `LookupAccountSidA` | Resolve SID to domain and username |
| `CloseHandle` | Close token handle |

## MITRE ATT&CK Mapping

- **T1033** - System Owner/User Discovery
