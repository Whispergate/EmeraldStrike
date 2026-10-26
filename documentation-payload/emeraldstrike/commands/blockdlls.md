+++
title = "blockdlls"
chapter = false
weight = 103
+++

## Summary

Block non-Microsoft-signed DLLs from loading in child processes spawned by the agent. This prevents EDR/AV DLL injection into sacrifice processes.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | Choice (start, stop) | Yes | - | Enable or disable DLL blocking |

### Usage

```
blockdlls -action start
blockdlls -action stop
```

## Detailed Summary

When enabled, child processes created by the agent (via `spawn`, `shell`, `run`, `execute`, etc.) are started with the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` mitigation policy. This is applied via `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` on the `STARTUPINFOEX` structure.

This causes the Windows loader to reject any DLL that is not signed by Microsoft, preventing EDR/AV hooking DLLs from being injected into the child process.

**Start**: Enables the mitigation flag for future child processes.
**Stop**: Disables the mitigation flag, reverting to default behavior.

## MITRE ATT&CK Mapping

- **T1562.001** - Impair Defenses: Disable or Modify Tools

## OPSEC Considerations

{{% notice info %}}
This is a defensive technique that prevents third-party DLLs from loading in child processes. It only affects processes spawned by the agent after the flag is set. The beacon's own process is not affected. Some legitimate software also uses this flag, so its presence is not inherently suspicious, but it may prevent EDR from monitoring child processes.
{{% /notice %}}

## Limitations

- Only affects child processes created after the flag is set.
- Does not affect the beacon's own process.
- Blocks all non-Microsoft DLLs, including legitimate third-party libraries the target process may need.
