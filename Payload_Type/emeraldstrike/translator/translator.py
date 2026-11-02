import struct
import base64
import json
import uuid
import logging

from mythic_container.TranslationBase import *

logger = logging.getLogger("emeraldstrike.translator")

TLV_TYPE_UUID     = 0x01
TLV_TYPE_TASKID   = 0x02
TLV_TYPE_COMMAND  = 0x03
TLV_TYPE_DATA     = 0x04
TLV_TYPE_STATUS   = 0x05
TLV_TYPE_OUTPUT   = 0x06
TLV_TYPE_ERROR    = 0x07
TLV_TYPE_FILEID   = 0x08
TLV_TYPE_FILEDATA = 0x09
TLV_TYPE_HOST      = 0x10
TLV_TYPE_USER      = 0x11
TLV_TYPE_PID       = 0x12
TLV_TYPE_IPS       = 0x13
TLV_TYPE_ARCH      = 0x14
TLV_TYPE_DOMAIN    = 0x15
TLV_TYPE_INTEGRITY = 0x16
TLV_TYPE_EXT_IP    = 0x17
TLV_TYPE_PROCNAME  = 0x18
TLV_TYPE_OS_INFO   = 0x19

# Task id -> agent-registered file_id, shared between the translator (which sees
# the file_id Mythic returns in get_tasking responses) and the payload container
# code (screenshot.py process_response), which runs in the same container.
FILE_ID_MAP_PATH = "/Mythic/file_id_map.json"


def _save_file_id_map(get_tasking_msg):
    try:
        mapping = {}
        for t in get_tasking_msg.get("tasks", []):
            fid = t.get("file_id")
            if fid and t.get("id"):
                mapping[str(t["id"])] = fid
        # Mythic replies to agent post_responses at the TOP LEVEL of the
        # get_tasking message: {"responses": [{"task_id","file_id",...}, ...]}
        for r in get_tasking_msg.get("responses", []) or []:
            rid = r.get("file_id")
            tid = r.get("task_id")
            if rid and tid:
                mapping[str(tid)] = rid
        if not mapping:
            return
        import json as _json
        import os as _os
        merged = {}
        if _os.path.exists(FILE_ID_MAP_PATH):
            try:
                with open(FILE_ID_MAP_PATH) as f:
                    merged = _json.load(f)
            except Exception:
                merged = {}
        merged.update(mapping)
        # keep it bounded
        if len(merged) > 200:
            merged = dict(sorted(merged.items())[-100:])
        with open(FILE_ID_MAP_PATH, "w") as f:
            _json.dump(merged, f)
    except Exception as e:
        logger.error(f"_save_file_id_map error: {e}")


def action_is_get_tasking_with_file(msg):
    if msg.get("action") != "get_tasking":
        return False
    if any(r.get("file_id") for r in msg.get("responses", []) or []):
        return True
    for t in msg.get("tasks", []):
        if t.get("file_id") or any(r.get("file_id") for r in t.get("responses", []) or []):
            return True
    return False


def _looks_like_ps_listing(out: bytes) -> bool:
    """Every non-empty line is 'pid\\tppid\\t[user\\t]name' with numeric pid/ppid."""
    lines = [l for l in out.decode("utf-8", errors="replace").splitlines() if l.strip()]
    if len(lines) < 2:
        return False
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
            return False
    return True


def _pack_tlv(tlv_type, data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return struct.pack(">BI", tlv_type, len(data)) + data


def _unpack_tlvs(buf):
    tlvs = {}
    pos = 0
    while pos + 5 <= len(buf):
        tlv_type = buf[pos]
        length = struct.unpack(">I", buf[pos+1:pos+5])[0]
        pos += 5
        if pos + length > len(buf):
            break
        tlvs[tlv_type] = buf[pos:pos+length]
        pos += length
    return tlvs


def _pack_int32(val):
    return struct.pack(">I", int(val))


def _pack_string(val):
    data = str(val).encode("utf-8") if not isinstance(val, bytes) else val
    return struct.pack(">I", len(data)) + data


def _pack_b64_bytes(val):
    raw = base64.b64decode(val)
    return struct.pack(">I", len(raw)) + raw


# Parameter schemas: ordered list of (param_name, pack_type)
# "int32" = 4-byte big-endian int, "string" = length-prefixed UTF-8, "b64" = base64-decoded length-prefixed bytes
_CMD_SCHEMAS = {
    "shell":           [("command", "string")],
    "ls":              [("path", "string")],
    "cd":              [("path", "string")],
    "cat":             [("path", "string")],
    "upload":          [("remote_path", "string"), ("file_data", "b64")],
    "download":        [("path", "string")],
    "sleep":           [("interval", "int32"), ("jitter", "int32")],
    "kill":            [("pid", "int32")],
    "cp":              [("source", "string"), ("destination", "string")],
    "mv":              [("source", "string"), ("destination", "string")],
    "rm":              [("path", "string")],
    "mkdir":           [("path", "string")],
    "inject":          [("pid", "int32"), ("shellcode_data", "b64")],
    "inline_execute":  [("bof_data", "b64"), ("bof_args", "b64")],
    "config":          [("action", "string"), ("key", "string"), ("value", "int32")],
    "spawnto_x64":     [("application", "string"), ("arguments", "string")],
    "spawnto_x86":     [("application", "string"), ("arguments", "string")],
    "spawn":           [("pid", "int32"), ("shellcode_data", "b64")],
    "argue":             [("action", "string"), ("fake_args", "string")],
    "execute_assembly":  [("assembly_data", "b64"), ("arguments", "string")],
    "powerpick":         [("runner_data", "b64"), ("script", "string")],
    "exit":              [("method_int", "int32")],
    "run":               [("executable", "string"), ("arguments", "string")],
    "execute":           [("executable", "string"), ("arguments", "string")],
    "ppid":              [("pid", "int32")],
    "steal_token":       [("pid", "int32")],
    "make_token":        [("domain", "string"), ("username", "string"), ("password", "string")],
    "blockdlls":         [("action", "string")],
    "argue":             [("action", "string"), ("fake_args", "string")],
}


def _pack_params(command, params):
    if not isinstance(params, dict) or not params:
        return b""

    schema = _CMD_SCHEMAS.get(command)
    if schema:
        result = b""
        for param_name, pack_type in schema:
            val = params.get(param_name)
            if val is None:
                if pack_type == "int32":
                    result += _pack_int32(0)
                else:
                    result += _pack_string("")
                continue
            if pack_type == "int32":
                result += _pack_int32(val)
            elif pack_type == "b64":
                result += _pack_b64_bytes(val)
            else:
                result += _pack_string(val)
        return result

    # Fallback: pack all values as length-prefixed strings
    result = b""
    for val in params.values():
        result += _pack_string(val)
    return result


class EmeraldStrikeTranslator(TranslationContainer):
    name = "EmeraldStrikeTranslator"
    description = "Binary TLV translator for EmeraldStrike agent"
    author = "@Lavender-exe"

    async def generate_keys(
        self, inputMsg: TrGenerateEncryptionKeysMessage
    ) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        response.DecryptionKey = b""
        response.EncryptionKey = b""
        return response

    async def translate_to_c2_format(
        self, inputMsg: TrMythicC2ToCustomMessageFormatMessage
    ) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        try:
            msg = inputMsg.Message
            if isinstance(msg, str):
                msg = json.loads(msg)

            # Mythic's reply to an agent post_response carries the registered
            # file_id: {"responses":[{"task_id","file_id"}]} (no action key).
            # Stash task_id -> file_id so the payload container (screenshot.py
            # process_response) can pick it up.
            if isinstance(msg.get("responses"), list) and msg["responses"]:
                _save_file_id_map({"responses": msg["responses"]})
                # nothing to send back to the agent for this reply
                response.Message = b""
                return response

            buf = b""
            action = msg.get("action", "")
            if action == "get_tasking" and "tasks" in msg and msg["tasks"]:
                task = msg["tasks"][0]
                command = task.get("command", "")
                buf += _pack_tlv(TLV_TYPE_COMMAND, command)
                buf += _pack_tlv(TLV_TYPE_TASKID, task.get("id", ""))
                params = task.get("parameters", "")
                if isinstance(params, str):
                    try:
                        params = json.loads(params)
                    except Exception:
                        pass
                params_packed = _pack_params(command, params) if isinstance(params, dict) else b""
                buf += _pack_tlv(TLV_TYPE_DATA, params_packed)
            elif action == "checkin":
                if "id" in msg:
                    buf += _pack_tlv(TLV_TYPE_TASKID, msg["id"])
                buf += _pack_tlv(TLV_TYPE_COMMAND, "checkin")
            elif action == "post_response":
                buf += _pack_tlv(TLV_TYPE_COMMAND, "post_response")
            else:
                if "id" in msg:
                    buf += _pack_tlv(TLV_TYPE_TASKID, msg["id"])
                buf += _pack_tlv(TLV_TYPE_COMMAND, action)

            response.Message = buf
        except Exception as e:
            logger.error(f"translate_to_c2_format error: {e}")
            response.Success = False
            response.Error = str(e)
        return response

    async def translate_from_c2_format(
        self, inputMsg: TrCustomMessageToMythicC2FormatMessage
    ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        try:
            raw = inputMsg.Message
            if isinstance(raw, str):
                raw = raw.encode("utf-8")

            if len(raw) == 0:
                response.Success = False
                response.Error = "empty message after UUID stripping"
                return response

            try:
                response.Message = json.loads(raw)
                return response
            except Exception:
                pass

            tlvs = _unpack_tlvs(raw)
            msg = {}

            if TLV_TYPE_UUID in tlvs and TLV_TYPE_HOST in tlvs:
                msg["action"] = "checkin"
                msg["uuid"] = tlvs[TLV_TYPE_UUID].decode("utf-8")
                msg["host"] = tlvs[TLV_TYPE_HOST].decode("utf-8", errors="replace")
                if TLV_TYPE_USER in tlvs:
                    msg["user"] = tlvs[TLV_TYPE_USER].decode("utf-8", errors="replace")
                if TLV_TYPE_PID in tlvs:
                    pid_bytes = tlvs[TLV_TYPE_PID]
                    if len(pid_bytes) == 4:
                        msg["pid"] = struct.unpack(">I", pid_bytes)[0]
                if TLV_TYPE_IPS in tlvs:
                    raw_ips = tlvs[TLV_TYPE_IPS].decode("utf-8", errors="replace")
                    msg["ips"] = [ip.strip() for ip in raw_ips.split(";") if ip.strip()]
                if TLV_TYPE_DOMAIN in tlvs:
                    msg["domain"] = tlvs[TLV_TYPE_DOMAIN].decode("utf-8", errors="replace")
                if TLV_TYPE_ARCH in tlvs:
                    msg["architecture"] = tlvs[TLV_TYPE_ARCH].decode("utf-8", errors="replace")
                if TLV_TYPE_OS_INFO in tlvs:
                    msg["os"] = tlvs[TLV_TYPE_OS_INFO].decode("utf-8", errors="replace")
                else:
                    msg["os"] = "Windows"
                if TLV_TYPE_PROCNAME in tlvs:
                    msg["process_name"] = tlvs[TLV_TYPE_PROCNAME].decode("utf-8", errors="replace")
                if TLV_TYPE_INTEGRITY in tlvs:
                    ib = tlvs[TLV_TYPE_INTEGRITY]
                    if len(ib) == 4:
                        msg["integrity_level"] = struct.unpack(">I", ib)[0]
                if TLV_TYPE_EXT_IP in tlvs:
                    eip = tlvs[TLV_TYPE_EXT_IP].decode("utf-8", errors="replace")
                    if eip:
                        msg["external_ip"] = eip
                response.Message = msg
                return response

            if TLV_TYPE_UUID in tlvs:
                msg["uuid"] = tlvs[TLV_TYPE_UUID].decode("utf-8")

            if TLV_TYPE_COMMAND in tlvs:
                cmd = tlvs[TLV_TYPE_COMMAND].decode("utf-8")
                msg["action"] = cmd
                if cmd == "get_tasking":
                    msg["tasking_size"] = 1

            if TLV_TYPE_TASKID in tlvs:
                msg["id"] = tlvs[TLV_TYPE_TASKID].decode("utf-8")

            if TLV_TYPE_DATA in tlvs:
                try:
                    msg["data"] = json.loads(tlvs[TLV_TYPE_DATA])
                except Exception:
                    msg["data"] = base64.b64encode(tlvs[TLV_TYPE_DATA]).decode()

            if TLV_TYPE_OUTPUT in tlvs:
                out = tlvs[TLV_TYPE_OUTPUT]
                if out.startswith(b"ESPNG:"):
                    # screenshot: magic + PNG bytes -> single-chunk Mythic download
                    png = out[6:]
                    msg["screenshot_png"] = base64.b64encode(png).decode()
                    msg["user_output"] = f"Screenshot captured ({len(png)} bytes)"
                elif out.startswith(b"ESDL:"):
                    # download: magic + int32 name_len + filename + int32 size + contents
                    rest = out[5:]
                    try:
                        name_len = struct.unpack(">I", rest[:4])[0]
                        filename = rest[4:4 + name_len].decode("utf-8", errors="replace")
                        fsize = struct.unpack(">I", rest[4 + name_len:8 + name_len])[0]
                        data = rest[8 + name_len:]
                        if len(data) != fsize:
                            raise ValueError(f"size mismatch: expected {fsize}, got {len(data)}")
                        msg["file_download"] = {
                            "filename": filename,
                            "data_b64": base64.b64encode(data).decode(),
                        }
                        msg["user_output"] = f"Downloaded {filename} ({fsize} bytes)"
                    except Exception as e:
                        logger.error(f"ESDL parse error: {e}")
                        msg["user_output"] = out.decode("utf-8", errors="replace")
                elif _looks_like_ps_listing(out):
                    # ps: "pid\tppid\t[user\t]name\n" lines -> JSON array for the ps
                    # browser script (same shape Starburst's translator emits)
                    procs = []
                    for line in out.decode("utf-8", errors="replace").splitlines():
                        parts = line.split("\t")
                        if len(parts) >= 4 and parts[0].isdigit() and parts[1].isdigit():
                            procs.append({
                                "process_id": int(parts[0]),
                                "parent_process_id": int(parts[1]),
                                "user": parts[2],
                                "name": "\t".join(parts[3:]),
                            })
                    if procs:
                        msg["user_output"] = json.dumps(procs)
                    else:
                        msg["user_output"] = out.decode("utf-8", errors="replace")
                else:
                    msg["user_output"] = out.decode("utf-8", errors="replace")

            if TLV_TYPE_ERROR in tlvs:
                msg["user_output"] = tlvs[TLV_TYPE_ERROR].decode("utf-8", errors="replace")
                msg["status"] = "error"

            if msg.get("action") == "post_response" and TLV_TYPE_TASKID in tlvs:
                task_id = tlvs[TLV_TYPE_TASKID].decode("utf-8")
                resp_entry = {"task_id": task_id}
                if "user_output" in msg:
                    resp_entry["user_output"] = msg.pop("user_output")
                if "screenshot_png" in msg:
                    resp_entry["download"] = {
                        "total_chunks": 1,
                        "chunk_num": 1,
                        "chunk_data": msg.pop("screenshot_png"),
                        "full_path": "screenshot.png",
                        "is_screenshot": True,
                    }
                    # makes Mythic route this to the container's
                    # process_response (screenshot.py), which then resolves
                    # the registered file_id for the browser script
                    resp_entry["process_response"] = "screenshot"
                if "file_download" in msg:
                    fd = msg.pop("file_download")
                    resp_entry["download"] = {
                        "total_chunks": 1,
                        "chunk_num": 1,
                        "chunk_data": fd["data_b64"],
                        "full_path": fd["filename"],
                    }
                if "status" in msg and msg["status"] == "error":
                    resp_entry["status"] = "error"
                    msg.pop("status")
                resp_entry["completed"] = True
                msg["responses"] = [resp_entry]
                msg.pop("id", None)

            response.Message = msg
        except Exception as e:
            logger.error(f"translate_from_c2_format error: {e}")
            response.Success = False
            response.Error = str(e)
        return response
