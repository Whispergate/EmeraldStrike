+++
title = "SMB"
chapter = false
weight = 10
+++

## Summary

SMB named pipe transport for peer-to-peer (P2P) agent linking. Allows agents without direct internet access to route traffic through a parent agent.

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Pipe Name | String | - | Named pipe name (without the `\\.\pipe\` prefix) |

## Architecture

The SMB transport creates a named pipe server on the target host. A parent agent (using HTTP or another egress channel) connects to the child's pipe and relays messages between the child and the Mythic server.

```
[Mythic Server] <--HTTP--> [Parent Agent] <--SMB Pipe--> [Child Agent]
```

This enables operations on hosts that cannot reach the C2 server directly, such as internal network segments behind a firewall.

## Transport Implementation

### Pipe Server

The agent creates a named pipe at `\\.\pipe\<pipename>` with:

- `PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED` - bidirectional, overlapped I/O
- `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE` - message-mode framing
- Single instance (`nMaxInstances = 1`)
- 64KB input and output buffers

After creation, the agent calls `ConnectNamedPipe` to wait for a parent agent to connect.

### Message I/O

- **Read**: Uses `PeekNamedPipe` to check for available data, then `ReadFile` to read the complete message into an allocated buffer.
- **Write**: Uses `WriteFile` to send a response message through the pipe.

Messages use the same binary TLV format as the HTTP transport. The parent agent handles encryption, base64 encoding, and forwarding to the Mythic server.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateNamedPipeA` | Create the named pipe server |
| `ConnectNamedPipe` | Wait for a parent agent to connect |
| `PeekNamedPipe` | Check for available data without blocking |
| `ReadFile` | Read message data from the pipe |
| `WriteFile` | Write response data to the pipe |

## MITRE ATT&CK Mapping

- **T1570** - Lateral Tool Transfer
- **T1071.002** - Application Layer Protocol: File Transfer Protocols

## OPSEC Considerations

{{% notice warning %}}
Named pipes are a well-known C2 channel. EDR products and Sysmon (Event ID 17/18) monitor pipe creation and connection events. The pipe name should be chosen to blend with legitimate Windows named pipes.
{{% /notice %}}

- Pipe creation is logged by Sysmon Event ID 17 (PipeCreated)
- Pipe connections are logged by Sysmon Event ID 18 (PipeConnected)
- Default pipe names like `msagent_*` or `postex_*` are signature-detected - use a realistic pipe name
- SMB traffic between hosts may be visible to network monitoring
- Single pipe instance means only one parent can connect at a time

## Limitations

- The child agent cannot initiate egress on its own - it requires a parent agent to connect to its pipe.
- Single instance pipe - only one parent connection at a time.
- Pipe name is set at build time and cannot be changed at runtime.
