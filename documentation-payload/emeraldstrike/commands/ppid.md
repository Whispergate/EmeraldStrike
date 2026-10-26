+++
title = "ppid"
chapter = false
weight = 103
+++

## Summary

Set the parent PID for child processes. Spawned processes will appear as children of the specified PID instead of the beacon's host process. Use 0 to reset to default behavior.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| pid | Number | Yes | 0 | PID to use as parent for child processes. Set to 0 to clear. |

### Usage

```
ppid -pid 612
ppid -pid 0
```

## Detailed Summary

Configures parent PID spoofing for future child processes. When set, the agent uses `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` and a handle to the specified process as the parent. This causes the child process to appear as a child of the spoofed PID in process trees.

**Set (pid > 0)**: Opens the target process and stores the handle for use with `STARTUPINFOEX` in future process creation calls.
**Clear (pid = 0)**: Closes the stored handle and reverts to normal process creation.

## MITRE ATT&CK Mapping

- **T1134.004** - Access Token Manipulation: Parent PID Spoofing

## OPSEC Considerations

{{% notice warning %}}
Parent PID spoofing changes the apparent parent in process trees but does not fool all detection mechanisms. ETW `ProcessStart` events record the real parent. Some EDR products compare the ETW parent with the PEB parent and flag mismatches. The agent must have `PROCESS_CREATE_PROCESS` access to the target parent PID.
{{% /notice %}}

## Limitations

- Requires appropriate access rights to open the target parent process.
- Does not affect processes already running -- only future child processes.
- ETW-based detection can still identify the real parent process.
