+++
title = "jobs"
chapter = false
weight = 103
+++

## Summary

List all running background jobs (long-running tasks, SOCKS proxies, port forwards).

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

None.

### Usage

```
jobs
```

## Detailed Summary

Queries the agent's internal job table and returns a listing of all active background jobs. Each entry includes a job ID, type, and description. Job IDs can be used with `jobkill` to terminate specific jobs.

Background jobs include:
- SOCKS proxy listeners
- Reverse port forwards
- Long-running command threads

## MITRE ATT&CK Mapping

None (agent-internal query only).
