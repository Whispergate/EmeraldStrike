+++
title = "mv"
chapter = false
weight = 103
+++

## Summary

Move or rename a file.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **source** (String, required) - Source file path.
- **destination** (String, required) - Destination file path.

### Usage

```
mv C:\Users\Public\old_name.txt C:\Users\Public\new_name.txt
```

## Detailed Summary

Moves or renames a file using `MoveFileA`. The operation will fail if the destination file already exists - no overwrite flag is set.

## MITRE ATT&CK Mapping

- **T1106** - Native API

## Limitations

- Cannot overwrite an existing destination file - `MoveFileA` does not use `MOVEFILE_REPLACE_EXISTING`.
