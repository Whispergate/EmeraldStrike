+++
title = "cat"
chapter = false
weight = 103
+++

## Summary

Read and display the contents of a file.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **path** (String, required) - Full path of the file to read.

### Usage

```
cat C:\Windows\win.ini
```

**Example Output:**

```
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

## Detailed Summary

Opens the target file with `CreateFileA` (read-only access, `FILE_SHARE_READ`), determines size via `GetFileSize`, allocates a buffer, reads the entire file in a single `ReadFile` call, and returns the raw bytes as the response.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateFileA` | Open file for reading |
| `GetFileSize` | Determine file size |
| `ReadFile` | Read file contents |
| `CloseHandle` | Close file handle |

## MITRE ATT&CK Mapping

- **T1005** - Data from Local System

## Limitations

- Reads the entire file into memory at once with no size limit - very large files could exhaust agent memory.
- File size is determined using only the low 32-bit DWORD, limiting support to files under 4GB.
- Returns raw bytes - binary files will produce unreadable output. Use `download` for binary files.
