#include "config.h"
#ifdef INCLUDE_CMD_UNLINK

#include "commands.h"


// unlink <callback_uuid>
// Tear down the link to a peer registered by cmd_link: close the client pipe
// handle, drop the registry entry, and queue ACTION_LINK_REMOVE for Mythic.
VOID cmd_unlink(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD uuid_len = 0;
    char* cb_uuid = parser_string(args, &uuid_len);

    if (!cb_uuid || uuid_len == 0) {
        package_add_string(inst, response, XSTR("usage: unlink <callback_uuid>"));
        response->is_error = TRUE;
        return;
    }

    char uuid_buf[37] = {0};
    es_memcpy(uuid_buf, (PVOID)cb_uuid, uuid_len < sizeof(uuid_buf) - 1 ? uuid_len : sizeof(uuid_buf) - 1);

    int removed = 0;
    for (int i = 0; i < ES_MAX_LINKED_PEERS; i++) {
        if (!inst->LinkedPeers[i].active) continue;
        if (es_strcmp(inst->LinkedPeers[i].uuid, uuid_buf) != 0) continue;

        // ── Queue ACTION_LINK_REMOVE message for Mythic ──
        // Format: ACTION_LINK_REMOVE(0x07) + link_id(int32, slot) + uuid(len-prefixed string)
        DWORD pu_len = es_strlen(inst->LinkedPeers[i].uuid);
        DWORD rm_msg_len = 1 + 4 + 4 + pu_len;
        BYTE* rm_msg = (BYTE*)es_malloc(inst, rm_msg_len);
        if (rm_msg) {
            DWORD rp = 0;
            rm_msg[rp++] = 0x07;  // ACTION_LINK_REMOVE
            // link_id (big-endian int32)
            rm_msg[rp++] = (BYTE)((i >> 24) & 0xFF);
            rm_msg[rp++] = (BYTE)((i >> 16) & 0xFF);
            rm_msg[rp++] = (BYTE)((i >> 8)  & 0xFF);
            rm_msg[rp++] = (BYTE)( i        & 0xFF);
            // peer_uuid (length-prefixed string)
            rm_msg[rp++] = (BYTE)((pu_len >> 24) & 0xFF);
            rm_msg[rp++] = (BYTE)((pu_len >> 16) & 0xFF);
            rm_msg[rp++] = (BYTE)((pu_len >> 8)  & 0xFF);
            rm_msg[rp++] = (BYTE)( pu_len        & 0xFF);
            es_memcpy(rm_msg + rp, (PVOID)inst->LinkedPeers[i].uuid, pu_len);
            rp += pu_len;

            extern void queue_pending_msg(PINSTANCE, BYTE*, DWORD);
            queue_pending_msg(inst, rm_msg, rp);
        }

        if (inst->LinkedPeers[i].pipe && inst->LinkedPeers[i].pipe != INVALID_HANDLE_VALUE)
            inst->Win32.CloseHandle(inst->LinkedPeers[i].pipe);
        inst->LinkedPeers[i].pipe = NULL;
        inst->LinkedPeers[i].active = FALSE;
        inst->LinkedPeers[i].uuid[0] = 0;
        inst->LinkedPeers[i].host[0] = 0;
        inst->LinkedPeers[i].pipename[0] = 0;
        if (inst->LinkedPeers[i].delegate_checkin_b64) {
            es_free(inst, inst->LinkedPeers[i].delegate_checkin_b64);
            inst->LinkedPeers[i].delegate_checkin_b64 = NULL;
            inst->LinkedPeers[i].delegate_checkin_b64_len = 0;
        }
        if (inst->LinkedPeerCount > 0) inst->LinkedPeerCount--;
        removed++;
    }

    if (removed == 0) {
        package_add_string(inst, response, XSTR("No active link for that host"));
        response->is_error = TRUE;
        return;
    }

    char msg[64] = {0};
    char* p = msg;
    const char* pre = "Unlinked (";
    for (int i = 0; pre[i]; i++) *p++ = pre[i];
    // removed count as digit
    *p++ = '0' + (char)removed;
    const char* tail = " link(s))";
    for (int i = 0; tail[i]; i++) *p++ = tail[i];
    *p = 0;
    package_add_string(inst, response, msg);
}

#endif // INCLUDE_CMD_UNLINK
