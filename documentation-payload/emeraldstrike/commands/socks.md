+++
title = "socks"
chapter = false
weight = 103
+++

## Summary

Start or stop a SOCKS5 proxy. Mythic opens a local TCP listener on the operator's machine; the agent relays TCP connections to the target network through the C2 channel.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | Choice (start, stop) | Yes | - | Start or stop the SOCKS proxy |
| port | Number | No | 1080 | Local port for Mythic's SOCKS listener |

### Usage

```
socks -action start -port 9050
socks -action start
socks -action stop
```

## Detailed Summary

**Start**: Tells Mythic to open a SOCKS5 listener on the specified port. The agent initializes Winsock and begins processing SOCKS connection requests relayed through the C2 channel. The agent resolves hostnames and establishes TCP connections on behalf of the proxied client.

When SOCKS is active, the agent reduces its sleep interval to 200ms to minimize tunnel latency. The normal sleep interval resumes when all SOCKS connections close.

**Stop**: Closes all active tunneled TCP connections and stops processing SOCKS data. The agent returns to its normal sleep interval.

### Connection Limits

The agent maintains up to 32 concurrent SOCKS connections. Each connection relays data bidirectionally between Mythic and the target host.

### Supported Address Types

- IPv4 addresses (SOCKS5 ATYP 0x01)
- Domain names with DNS resolution (SOCKS5 ATYP 0x03)
- IPv6 is not supported (SOCKS5 ATYP 0x04 returns address-type-not-supported)

## MITRE ATT&CK Mapping

- **T1090** - Proxy

## OPSEC Considerations

{{% notice info %}}
SOCKS traffic is encapsulated within the existing C2 channel -- no additional listening ports are opened on the target. However:

- The agent makes outbound TCP connections to proxied destinations, which may be unusual for the host process.
- The 200ms polling interval increases C2 beacon frequency significantly while SOCKS is active.
- High-volume proxy traffic increases C2 channel bandwidth and may trigger data exfiltration alerts.
- ws2_32.dll is loaded dynamically when SOCKS starts; this may be unusual for the host process.
{{% /notice %}}
