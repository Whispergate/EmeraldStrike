+++
title = "socks"
chapter = false
weight = 103
+++

## Summary

Start or stop a SOCKS4a proxy. Traffic is tunneled through the beacon's C2 channel, enabling the operator to proxy tools through the compromised host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | Choice (start, stop) | Yes | - | Start or stop the SOCKS proxy |
| port | Number | No | 1080 | Local port to listen on (for start) |

### Usage

```
socks -action start -port 9050
socks -action start
socks -action stop
```

## Detailed Summary

**Start**: Creates a SOCKS4a proxy listener on the beacon. Incoming connections from the operator's tools (via `proxychains`, browser settings, etc.) are forwarded through the C2 channel to the target network. The beacon resolves hostnames and establishes TCP connections on behalf of the client.

**Stop**: Tears down the SOCKS proxy listener and closes all active tunneled connections.

The proxy runs as a background job visible in the `jobs` listing and can be killed with `jobkill`.

## MITRE ATT&CK Mapping

- **T1090** - Proxy

## OPSEC Considerations

{{% notice info %}}
SOCKS traffic is encapsulated within the existing C2 channel -- no additional network connections are created from the beacon. However, the beacon makes outbound connections to the proxied destinations, which may be unusual for the host process. High-volume proxy traffic increases C2 channel bandwidth and may trigger data exfiltration alerts.
{{% /notice %}}
