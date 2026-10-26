+++
title = "config"
chapter = false
weight = 103
+++

## Summary

View or modify the agent's runtime configuration (sleep, jitter, killdate).

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **action** (ChooseOne: "get"/"set", optional) - Whether to view or modify configuration. Default: "get".
- **key** (String, optional) - Configuration key to set (sleep, jitter, killdate). Default: empty.
- **value** (Number, optional) - New value for the key. Default: 0.

### Usage

View current configuration:

```
config
```

**Example Output:**

```
uuid=abc123 sleep=5000 jitter=10 killdate=0
```

Change sleep interval (in milliseconds):

```
config -action set -key sleep -value 5000
```

Change jitter percentage:

```
config -action set -key jitter -value 25
```

## Detailed Summary

**Get/View mode** (default): Returns current agent configuration values including UUID, sleep interval (in milliseconds), jitter percentage, and killdate timestamp.

**Set mode**: Modifies a single configuration key. The key is matched by its first character:
- `s` -> sets `sleep_ms` (value is in raw milliseconds, unlike the `sleep` command which takes seconds)
- `j` -> sets `jitter` percentage
- `k` -> sets `killdate` unix timestamp

A killdate of 0 means no kill date is set. When set, the agent checks the killdate against the current time at each beacon cycle and exits if the date has passed.

## MITRE ATT&CK Mapping

None.

## Limitations

- The `set` action takes sleep values in raw milliseconds, not seconds. Use the `sleep` command for a more intuitive seconds-based interface.
