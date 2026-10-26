+++
title = "sleep"
chapter = false
weight = 103
+++

## Summary

Change the agent's callback interval and jitter percentage.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **interval** (Number, required) - Sleep interval in seconds.
- **jitter** (Number, optional) - Jitter percentage (0-100). Default: 0.

### Usage

```
sleep 30 20
```

Sets the callback interval to 30 seconds with 20% jitter.

```
sleep 60
```

Sets the callback interval to 60 seconds, keeping current jitter.

## Detailed Summary

The sleep command updates the agent's `sleep_ms` and `jitter` fields. The interval value is provided in seconds by the operator and converted to milliseconds by the agent (multiplied by 1000). Jitter values above 100 are silently ignored, keeping the existing value.

If the interval is 0, the existing sleep value is preserved. Jitter introduces randomness to each sleep cycle - with a 60-second interval and 20% jitter, each sleep will be between 48 and 72 seconds.

## MITRE ATT&CK Mapping

None.
