+++
title = "powershell_import"
chapter = false
weight = 103
+++

## Summary

Import a PowerShell script into memory for use with subsequent `powerpick` commands. Importing a new script replaces any previously imported script.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| file | File | Yes | - | PowerShell .ps1 script to import |

### Usage

```
powershell_import -file <PowerView.ps1>
powershell_import -file <Invoke-Mimikatz.ps1>
```

## Detailed Summary

This is a server-side command. It stores the PowerShell script in Mythic's file store as `psimport_active.ps1` for retrieval by the agent when `powerpick` is called.

1. Reads the uploaded file content and decodes it as UTF-8 (handles BOM via `utf-8-sig`).
2. Validates the script is not empty.
3. Deletes any previously stored `psimport_active.ps1` to enforce a single-active-import model.
4. Creates the new file in the store.

Only one imported script is active at a time. Importing a new script replaces the old one.

## MITRE ATT&CK Mapping

- **T1059.001** - Command and Scripting Interpreter: PowerShell

## OPSEC Considerations

{{% notice warning %}}
The imported script is stored in Mythic's file store and sent to the agent when `powerpick` is called. The agent loads it via CLR-hosted PowerShell, which may be detected by AMSI (unless AMSI patching is enabled at build time). The script contents never touch disk on the target.
{{% /notice %}}

## Limitations

- Only one imported script is active at a time.
- The script is not sent to the agent until a `powerpick` command is issued.
