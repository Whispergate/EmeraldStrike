+++
title = "make_token"
chapter = false
weight = 103
+++

## Summary

Create a new logon token with the specified credentials and impersonate it. The token uses `LOGON32_LOGON_NEW_CREDENTIALS`, which means it only applies to network authentication -- local operations still use the original token.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| domain | String | Yes | - | Domain for logon (use `.` for local) |
| username | String | Yes | - | Username |
| password | String | Yes | - | Password |

### Usage

```
make_token -domain CORP -username admin -password P@ssw0rd
make_token CORP\admin P@ssw0rd
```

## Detailed Summary

Creates a logon token with the provided credentials using `LogonUserA` with `LOGON32_LOGON_NEW_CREDENTIALS`. This token type is used for outbound network authentication (SMB, WinRM, LDAP, etc.) while local file system access continues to use the original process token.

1. Calls `LogonUserA` with the domain, username, password, and `LOGON32_LOGON_NEW_CREDENTIALS` logon type.
2. Applies the resulting token via `ImpersonateLoggedOnUser`.
3. The token persists until `rev2self` is called.

### APIs Used

| API | Purpose |
|-----|---------|
| `LogonUserA` | Create logon token with credentials |
| `ImpersonateLoggedOnUser` | Apply token to current thread |

## MITRE ATT&CK Mapping

- **T1134.003** - Access Token Manipulation: Make and Impersonate Token

## OPSEC Considerations

{{% notice info %}}
`LOGON32_LOGON_NEW_CREDENTIALS` does not validate credentials locally. The token is always created successfully, even with incorrect credentials -- authentication failures only surface when the token is used for network access. A logon event (Event ID 4624, logon type 9) is generated.
{{% /notice %}}

## Limitations

- The token only applies to network authentication. Local operations (file I/O, registry) use the original token.
- Credentials are not validated at token creation time.
