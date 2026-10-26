+++
title = "ps"
chapter = false
weight = 103
+++

## Summary

List running processes with PID, PPID, and process name.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
ps
```

## Detailed Summary

Enumerates all running processes using `CreateToolhelp32Snapshot` with the `TH32CS_SNAPPROCESS` flag. Iterates entries with `Process32First` / `Process32Next`.

For each process, returns a tab-delimited line containing:
- Process ID (PID)
- Parent Process ID (PPID)
- Process name

Results are returned as structured output for Mythic's process browser integration.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateToolhelp32Snapshot` | Create a snapshot of running processes |
| `Process32First` | Get the first process entry |
| `Process32Next` | Iterate remaining process entries |
| `CloseHandle` | Clean up snapshot handle |

## MITRE ATT&CK Mapping

- **T1057** - Process Discovery

## Limitations

- Only returns PID, PPID, and process name - no architecture, user context, or thread information.
