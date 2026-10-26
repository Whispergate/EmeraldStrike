+++
title = "unlink"
chapter = false
weight = 103
+++

## Summary

Disconnect from a linked P2P beacon.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| host | String | Yes | - | Host to disconnect from |

### Usage

```
unlink -host DC01
unlink -host 192.168.1.10
```

## Detailed Summary

Tears down the SMB named pipe P2P channel established by `link`. The linked beacon loses its communication path and will no longer check in through this parent beacon.

## MITRE ATT&CK Mapping

- **T1071.002** - Application Layer Protocol: File Transfer Protocols

## OPSEC Considerations

{{% notice info %}}
The linked beacon will stop communicating until re-linked or until it regains a direct C2 path. Unlinking does not kill or exit the child beacon.
{{% /notice %}}
