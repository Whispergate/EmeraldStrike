+++
title = "rev2self"
chapter = false
weight = 103
+++

## Summary

Revert to the agent's original access token, dropping any stolen or impersonated token.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

None.

### Usage

```
rev2self
```

## Detailed Summary

Calls `RevertToSelf()` to drop any thread impersonation token and return to the process's primary token. Also closes and clears any stored token handle from a previous `steal_token` or `make_token` call.

### APIs Used

| API | Purpose |
|-----|---------|
| `RevertToSelf` | Remove thread impersonation token |
| `CloseHandle` | Close the stored token handle |

## MITRE ATT&CK Mapping

- **T1134** - Access Token Manipulation
