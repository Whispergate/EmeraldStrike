+++
title = "upload"
chapter = false
weight = 103
+++

## Summary

Upload a file from the Mythic server to the target host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **file** (File, required) - File to upload (selected from Mythic's file browser or uploaded inline).
- **remote_path** (String, required) - Full destination path on the target, including filename.

### Usage

```
upload
```

A file dialog will appear in the Mythic UI to select the file and specify the remote path.

## Detailed Summary

The Python tasking handler fetches the file content from Mythic via `SendMythicRPCFileGetContent`, base64-encodes it, and sends it to the agent as a single blob.

On the agent side:

1. Parses the destination path string and file data bytes from the task parameters.
2. Creates the file with `CreateFileA` using `CREATE_ALWAYS` (overwrites any existing file).
3. Writes the entire payload in a single `WriteFile` call.
4. Closes the file handle.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateFileA` | Create destination file |
| `WriteFile` | Write file data |
| `CloseHandle` | Close file handle |

## MITRE ATT&CK Mapping

- **T1105** - Ingress Tool Transfer

## OPSEC Considerations

- Uses `CREATE_ALWAYS` - overwrites any existing file at the destination without warning.
- File write events may be logged by Sysmon or EDR file monitoring.
