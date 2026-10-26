+++
title = "rportfwd"
chapter = false
weight = 103
+++

## Summary

Start or stop a reverse port forward. The beacon listens on a port on the target machine and forwards incoming connections back through the C2 channel to a host and port accessible from the operator.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | Choice (start, stop) | Yes | - | Start or stop a reverse port forward |
| bind_port | Number | Yes | - | Port to listen on (on the target) |
| forward_host | String | No | 127.0.0.1 | Host to forward traffic to (from operator perspective) |
| forward_port | Number | No | (bind_port) | Port to forward traffic to |

### Usage

```
rportfwd -action start -bind_port 8080 -forward_host 10.0.0.5 -forward_port 80
rportfwd -action start -bind_port 445
rportfwd -action stop -bind_port 8080
```

## Detailed Summary

**Start**: The beacon binds a listening socket on the specified port on the target machine. When a connection arrives, the data is relayed through the C2 channel to the operator's infrastructure, which forwards it to the specified host and port. If `forward_port` is not specified, it defaults to `bind_port`.

**Stop**: Closes the listening socket and tears down all active forwarded connections for that port.

The port forward runs as a background job visible in the `jobs` listing.

## MITRE ATT&CK Mapping

- **T1090.001** - Proxy: Internal Proxy

## OPSEC Considerations

{{% notice warning %}}
The beacon opens a listening socket on the target, which is visible in `netstat` output and may trigger host-based firewall rules or network monitoring alerts. Binding to well-known ports (80, 443, 445) requires administrator privileges and may conflict with existing services.
{{% /notice %}}
