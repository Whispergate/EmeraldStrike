+++
title = "ls"
chapter = false
weight = 103
+++

## Summary

List files and directories at the specified path with metadata (name, size, type).

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **path** (String, optional) - Directory path to list. Default: current directory (`.`).

### Usage

```
ls C:\Users
```

```
ls
```

Lists the current working directory.

## Detailed Summary

Enumerates the target directory using `FindFirstFileA` / `FindNextFileA`. Appends `\*` to the provided path to form the search pattern.

For each entry, returns a tab-delimited line containing:
- Type indicator (`d` for directory, `-` for file)
- File size (low DWORD only)
- Filename

Results are returned as structured output for Mythic's file browser integration.

### APIs Used

| API | Purpose |
|-----|---------|
| `FindFirstFileA` | Begin directory enumeration |
| `FindNextFileA` | Continue enumeration |
| `FindClose` | Clean up search handle |

## MITRE ATT&CK Mapping

- **T1083** - File and Directory Discovery

## Limitations

- File sizes are reported using only the low 32-bit DWORD - files larger than 4GB show incorrect sizes.
- No timestamp information is included in the output.
