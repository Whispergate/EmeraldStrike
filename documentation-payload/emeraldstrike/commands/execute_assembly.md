+++
title = "execute_assembly"
chapter = false
weight = 103
+++

## Summary

Execute a .NET assembly in-process via CLR hosting. The assembly runs inside the beacon's process without spawning a child process.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

**Default parameter group (use a registered assembly):**

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| Assembly | ChooseOne (dynamic) | Yes | - | Previously registered .NET assembly |
| Arguments | String | No | "" | Arguments to pass to the assembly |

**New parameter group (upload a new assembly):**

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| assembly_file | File | Yes | - | .NET assembly to upload and execute |
| Arguments | String | No | "" | Arguments to pass to the assembly |

### Usage

```
execute_assembly -Assembly Seatbelt.exe -Arguments "-group=all"
execute_assembly -assembly_file <Rubeus.exe> -Arguments "triage"
```

## Detailed Summary

The Python tasking handler retrieves the assembly bytes (from the file store or a new upload), base64-encodes them, and sends them to the agent.

On the agent side:

1. Loads `mscoree.dll` and calls `CLRCreateInstance` to obtain an `ICLRMetaHost` interface.
2. Enumerates installed runtimes and gets the `.NET v4.0.30319` runtime via `GetRuntime`.
3. Obtains `ICorRuntimeHost`, starts the runtime, and gets the default `AppDomain`.
4. Redirects stdout/stderr to a named pipe (persistent across invocations for reuse).
5. Loads the assembly bytes into the AppDomain via `_AppDomain::Load_3`.
6. Retrieves the entry point via `_Assembly::get_EntryPoint`.
7. Splits space-separated arguments into a `SAFEARRAY` of `BSTR`.
8. Invokes the entry point via `_MethodInfo::Invoke_3`.
9. A background pipe reader thread captures stdout output and returns it.

### APIs Used

| API | Purpose |
|-----|---------|
| `CLRCreateInstance` | Initialize CLR hosting |
| `ICLRMetaHost::GetRuntime` | Get .NET v4.0.30319 runtime |
| `ICorRuntimeHost::Start` | Start the CLR |
| `ICorRuntimeHost::GetDefaultDomain` | Get default AppDomain |
| `_AppDomain::Load_3` | Load assembly bytes |
| `_MethodInfo::Invoke_3` | Execute assembly entry point |
| `CreateNamedPipeA` | Create pipe for stdout capture |

## MITRE ATT&CK Mapping

- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1106** - Native API

## OPSEC Considerations

{{% notice warning %}}
Loading the CLR into a non-.NET process is a well-known indicator. EDR products monitor for `clr.dll` and `mscoree.dll` being loaded into processes that are not typically .NET applications. The assembly runs in-process, so a crashing assembly will crash the beacon. AMSI and ETW patches (if compiled in) are applied before CLR initialization.
{{% /notice %}}

- CLR loading into the beacon process is visible in module load telemetry
- The assembly runs in the beacon's process space -- no child process is created
- stdout/stderr is captured via named pipe, which may appear in pipe enumeration

## Limitations

- Requires .NET Framework v4.0.30319 to be installed on the target.
- Arguments are split on spaces -- complex quoting is not supported.
- Assembly must have a standard `Main` entry point.
