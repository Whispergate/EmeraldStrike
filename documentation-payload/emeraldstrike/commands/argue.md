+++
title = "argue"
chapter = false
weight = 103
+++

## Summary

Set or clear fake command-line arguments for child processes. When set, spawned processes will have their PEB command line overwritten with the fake arguments after creation.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | Choice (set, clear) | Yes | set | Set or clear fake arguments |
| fake_args | String | No | - | Fake command-line arguments to display |

### Usage

```
argue -action set -fake_args "notepad.exe"
argue -action clear
```

## Detailed Summary

On the agent side:

1. **Set**: Allocates a buffer and stores the fake arguments string in `inst->argue_args`. Future calls to `CreateProcessA`/`CreateProcessW` by the agent will overwrite the child process's PEB `ProcessParameters.CommandLine` with these fake arguments after the process is created in a suspended state.
2. **Clear**: Frees the stored fake arguments and resets the pointer to NULL.

This is a form of argument spoofing -- the process is created with the real command line, then the PEB is patched before the process is resumed. Process creation logging (Sysmon Event ID 1, Security Event 4688) captures the real arguments at creation time, but tools that inspect the PEB at runtime (like Task Manager or Process Explorer) will see the fake arguments.

## MITRE ATT&CK Mapping

- **T1564.010** - Hide Artifacts: Process Argument Spoofing

## OPSEC Considerations

{{% notice info %}}
Argument spoofing only affects PEB-based inspection. ETW-based command line logging and Sysmon capture the real arguments at process creation time before the PEB is patched.
{{% /notice %}}
