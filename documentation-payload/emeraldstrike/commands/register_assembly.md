+++
title = "register_assembly"
chapter = false
weight = 103
+++

## Summary

Upload and register a .NET assembly (.exe or .dll) in Mythic's file store for later use with `execute_assembly`.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| file | File | Yes | - | .NET assembly (.exe or .dll) to register |

### Usage

```
register_assembly -file <Seatbelt.exe>
register_assembly -file <Rubeus.exe>
```

## Detailed Summary

This is a server-side-only command (`script_only=True`). It does not send anything to the agent.

1. Accepts a file upload and validates the extension is `.exe` or `.dll`.
2. Reads the file content via `SendMythicRPCFileGetContent`.
3. Re-creates the file in Mythic's persistent file store with `DeleteAfterFetch=False`.
4. The registered assembly then appears in the `execute_assembly` dropdown for reuse across tasks.

## MITRE ATT&CK Mapping

None (server-side file management only).

## Limitations

- Only `.exe` and `.dll` extensions are accepted.
- The assembly is stored server-side -- it is not pushed to the agent until `execute_assembly` is called.
