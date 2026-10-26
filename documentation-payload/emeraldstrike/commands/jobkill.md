+++
title = "jobkill"
chapter = false
weight = 103
+++

## Summary

Kill a running background job by its ID.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| job_id | Number | Yes | - | Job ID to kill (from `jobs` output) |

### Usage

```
jobkill -job_id 1
jobkill -job_id 3
```

## Detailed Summary

Terminates the background thread associated with the specified job ID and cleans up its resources (sockets, handles, memory). The job ID is obtained from the `jobs` command output.

## MITRE ATT&CK Mapping

None (agent-internal management only).
