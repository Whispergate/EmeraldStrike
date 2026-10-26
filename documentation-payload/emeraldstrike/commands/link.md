+++
title = "link"
chapter = false
weight = 103
+++

## Summary

Connect to an SMB beacon on a target host via named pipe for peer-to-peer communication.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| host | String | Yes | - | Target host to connect to |
| pipename | String | No | emeraldstrike | Named pipe name |

### Usage

```
link -host DC01 -pipename emeraldstrike
link -host 192.168.1.10
```

## Detailed Summary

Establishes a peer-to-peer link to another EmeraldStrike beacon that is listening on an SMB named pipe. The linked beacon's traffic is relayed through the parent beacon's C2 channel, enabling communication with beacons that do not have direct internet access.

1. Connects to `\\<host>\pipe\<pipename>` using `CreateFileA` / `ConnectNamedPipe`.
2. Establishes a bidirectional communication channel over the named pipe.
3. The linked beacon's task output and check-ins are relayed through this beacon.

## MITRE ATT&CK Mapping

- **T1071.002** - Application Layer Protocol: File Transfer Protocols

## OPSEC Considerations

{{% notice info %}}
SMB named pipe connections generate network traffic on port 445. The pipe name is visible to tools that enumerate named pipes (e.g., `Get-ChildItem \\.\pipe\`). Use a non-default pipe name for better operational security.
{{% /notice %}}

- SMB connection to the target host is visible in network logs
- The named pipe is enumerable on both endpoints
- Default pipe name `emeraldstrike` should be changed for production use
