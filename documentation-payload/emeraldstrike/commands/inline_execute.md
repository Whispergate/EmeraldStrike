+++
title = "inline_execute"
chapter = false
weight = 103
+++

## Summary

Execute a COFF (Common Object File Format) object file, commonly known as a BOF (Beacon Object File). Provides Beacon API compatibility for existing BOF tooling.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| bof_file | File | Yes | - | COFF/BOF object file (.o) to execute |
| arguments | String | No | "" | Arguments to pass to the BOF (raw bytes) |

### Usage

```
inline_execute -bof_file <bof.o> -arguments "arg1 arg2"
inline_execute -bof_file <bof.o>
```

## Detailed Summary

The Python tasking handler fetches the BOF content from Mythic via `SendMythicRPCFileGetContent`, base64-encodes it, and sends it to the agent along with any arguments.

On the agent side:

1. Parses COFF object data and optional argument bytes from the task parameters.
2. Passes both to the internal BOF execution engine (`bof_execute`).
3. The BOF engine parses the COFF file header, section headers, symbols, and relocations.
4. Allocates memory, copies sections, applies relocations, and resolves external symbols against the Beacon API function table.
5. Executes the `go` entry point with the argument buffer.
6. Captures output from `BeaconPrintf` / `BeaconOutput` calls and returns it.
7. Frees all allocated memory after execution.

### Supported Beacon APIs

| API | Description |
|-----|-------------|
| `BeaconPrintf` | Formatted string output |
| `BeaconOutput` | Raw data output |
| `BeaconDataParse` | Initialize argument parser |
| `BeaconDataInt` | Read 4-byte integer from args |
| `BeaconDataShort` | Read 2-byte integer from args |
| `BeaconDataLength` | Get remaining args length |
| `BeaconDataExtract` | Read length-prefixed string |
| `BeaconFormatAlloc` | Allocate format buffer |
| `BeaconFormatReset` | Reset format buffer |
| `BeaconFormatFree` | Free format buffer |
| `BeaconFormatAppend` | Append raw data |
| `BeaconFormatPrintf` | Append formatted string |
| `BeaconFormatToString` | Get formatted buffer |
| `BeaconFormatInt` | Append 4-byte integer |

## MITRE ATT&CK Mapping

- **T1059** - Command and Scripting Interpreter
- **T1106** - Native API

## OPSEC Considerations

{{% notice warning %}}
BOFs execute in the agent's thread - a crashing BOF will crash the agent. There is no sandboxing or exception handling around BOF execution.
{{% /notice %}}

- No process creation required - stealthier than `shell` for many operations
- Memory allocations for COFF sections may be visible to memory scanners
- BOF memory is freed after execution

## Limitations

- x64 BOFs only (when agent is x64).
- BOF must follow the standard Beacon API conventions.
- Arguments are passed as raw bytes - the caller is responsible for proper BOF argument packing.
