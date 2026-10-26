+++
title = "register_bof"
chapter = false
weight = 103
+++

## Summary

Upload and register a BOF (.o COFF object file) in Mythic's file store for later use with `inline_execute`.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| file | File | Yes | - | BOF object file (.o) to register |

### Usage

```
register_bof -file <whoami.x64.o>
register_bof -file <dir.x64.o>
```

## Detailed Summary

This is a server-side-only command (`script_only=True`). It does not send anything to the agent.

1. Accepts a file upload and validates the extension is `.o`.
2. Reads the file content via `SendMythicRPCFileGetContent`.
3. Re-creates the file in Mythic's persistent file store with `DeleteAfterFetch=False`.
4. The registered BOF then appears in the `inline_execute` file picker for reuse.

## MITRE ATT&CK Mapping

None (server-side file management only).

## Limitations

- Only `.o` extensions are accepted.
- The BOF is stored server-side -- it is not pushed to the agent until `inline_execute` is called.
