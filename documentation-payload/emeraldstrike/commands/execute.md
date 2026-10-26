+++
title = "execute"
chapter = false
weight = 103
+++

## Summary

Execute a program in the background without capturing output or waiting for completion. Fire-and-forget execution.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| executable | String | Yes | - | Path to executable |
| arguments | String | No | "" | Arguments to pass |

### Usage

```
execute notepad.exe
execute C:\Tools\payload.exe -silent
```

## Detailed Summary

Creates the specified process with `CreateProcessA` and immediately returns without waiting for completion or capturing output. The process runs independently of the beacon.

1. Calls `CreateProcessA` with the executable and arguments.
2. Closes process and thread handles immediately.
3. Returns success/failure to the operator.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateProcessA` | Spawn the executable |
| `CloseHandle` | Clean up handles |

## MITRE ATT&CK Mapping

- **T1106** - Native API

## OPSEC Considerations

{{% notice info %}}
Same process creation telemetry as `run`, but no pipe handles are created for output capture. The spawned process runs independently -- if it produces visible windows or other artifacts, those remain on the target.
{{% /notice %}}

## Limitations

- No output is captured -- use `run` or `shell` if you need to see command output.
- No timeout or monitoring -- the spawned process runs until it exits on its own.
