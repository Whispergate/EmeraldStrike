+++
title = "cd"
chapter = false
weight = 103
+++

## Summary

Change the agent's current working directory.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **path** (String, required) - Directory path to change to.

### Usage

```
cd C:\Users\Public
```

```
cd ..
```

## Detailed Summary

Calls `SetCurrentDirectoryA` with the provided path. On success, calls `GetCurrentDirectoryA` and returns the new working directory path as confirmation.

## MITRE ATT&CK Mapping

- **T1083** - File and Directory Discovery
