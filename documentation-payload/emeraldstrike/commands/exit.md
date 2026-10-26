+++
title = "exit"
chapter = false
weight = 100
+++

## Summary

Terminates the EmeraldStrike agent. The agent stops its beacon loop and the host process thread returns.

### Arguments

No arguments required.

### Usage

```
exit
```

### MITRE ATT&CK Mapping

None.

### OPSEC Considerations

- The host process may continue running after the agent exits - the shellcode thread simply returns.
- No artifacts are written to disk during exit.
