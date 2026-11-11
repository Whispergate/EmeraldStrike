"""
Mock Mythic Server for EmeraldStrike protocol testing.

Speaks the same binary TLV + AES256-CBC protocol as the real Mythic server.
Handles: checkin, get_tasking (with command queue), post_response.

Usage:
    python mock_mythic_server.py [--port 8080] [--aes-key hex] [--uuid UUID]

The server listens on HTTP and processes agent messages at /agent_message.
It logs all protocol exchanges and validates message structure.

TLV wire format: type (1B) + length (2B big-endian) + data
"""
import os
import sys
import json
import struct
import base64
import hashlib
import hmac
import argparse
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ── TLV type constants (must match translator.py) ──

TLV_TYPE_UUID     = 0x01
TLV_TYPE_TASKID   = 0x02
TLV_TYPE_COMMAND  = 0x03
TLV_TYPE_DATA     = 0x04
TLV_TYPE_STATUS   = 0x05
TLV_TYPE_OUTPUT   = 0x06
TLV_TYPE_ERROR    = 0x07
TLV_TYPE_FILEID   = 0x08
TLV_TYPE_FILEDATA = 0x09

# ── Default test values ──

DEFAULT_UUID = "11111111-1111-1111-1111-111111111111"
DEFAULT_AES_KEY = bytes.fromhex(
    "4142434445464748494a4b4c4d4e4f50"
    "5152535455565758595a616263646566"
)
CALLBACK_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def pack_tlv(tlv_type, data):
    """Pack a single TLV: type (1B) + length (2B BE) + data."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return struct.pack(">BH", tlv_type, len(data)) + data


def unpack_tlvs(buf):
    """Unpack a buffer into {type: data} dict."""
    tlvs = {}
    pos = 0
    while pos + 3 <= len(buf):
        tlv_type = buf[pos]
        length = struct.unpack(">H", buf[pos+1:pos+3])[0]
        pos += 3
        if pos + length > len(buf):
            break
        tlvs[tlv_type] = buf[pos:pos+length]
        pos += length
    return tlvs


class MockMythicState:
    """Shared state for the mock server."""

    def __init__(self, payload_uuid, aes_key, callback_uuid=CALLBACK_UUID):
        self.payload_uuid = payload_uuid
        self.aes_key = aes_key
        self.callback_uuid = callback_uuid
        self.checked_in = False
        self.checkin_data = None
        self.task_queue = []
        self.responses = []
        self.exchange_log = []
        self.lock = threading.RLock()

    def queue_task(self, command, params=None):
        """Queue a task for the agent to pick up."""
        import uuid as uuid_mod
        task_uuid = str(uuid_mod.uuid4())
        self.task_queue.append({
            "command": command,
            "id": task_uuid,
            "parameters": params or {},
        })
        return task_uuid

    def encrypt(self, plaintext):
        """AES256-CBC encrypt with HMAC, matching agent format."""
        if not HAS_CRYPTO:
            return plaintext

        iv = os.urandom(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded)

        mac = hmac.new(self.aes_key, iv + ciphertext, hashlib.sha256).digest()
        return iv + ciphertext + mac

    def decrypt(self, blob):
        """AES256-CBC decrypt with HMAC verification."""
        if not HAS_CRYPTO:
            return blob

        if len(blob) < 48:
            raise ValueError(f"blob too short: {len(blob)} bytes")

        iv = blob[:16]
        mac_received = blob[-32:]
        ciphertext = blob[16:-32]

        mac_computed = hmac.new(
            self.aes_key, iv + ciphertext, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(mac_received, mac_computed):
            raise ValueError("HMAC verification failed")

        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    def process_message(self, raw_body):
        """Process a raw HTTP body from the agent."""
        try:
            decoded = base64.b64decode(raw_body)
        except Exception as e:
            return self._error(f"base64 decode failed: {e}")

        if len(decoded) < 37:
            return self._error("message too short for UUID prefix")

        uuid_prefix = decoded[:36].decode("utf-8", errors="replace")
        encrypted_payload = decoded[36:]

        self._log("RECV", f"UUID prefix: {uuid_prefix}")

        request_was_encrypted = False
        tlv_data = None

        if HAS_CRYPTO and len(encrypted_payload) >= 48:
            try:
                tlv_data = self.decrypt(encrypted_payload)
                request_was_encrypted = True
            except ValueError:
                pass

        if tlv_data is None:
            tlv_data = encrypted_payload

        if len(tlv_data) < 1:
            return self._error("empty TLV payload")

        tlvs = unpack_tlvs(tlv_data)
        self._log("RECV", f"TLVs: {list(tlvs.keys())}, len={len(tlv_data)}")

        if TLV_TYPE_UUID in tlvs:
            response_tlv = self._handle_checkin(tlvs)
        elif TLV_TYPE_COMMAND in tlvs:
            cmd = tlvs[TLV_TYPE_COMMAND].decode("utf-8")
            if cmd == "get_tasking":
                response_tlv = self._handle_get_tasking(tlvs)
            elif cmd == "post_response":
                response_tlv = self._handle_post_response(tlvs)
            else:
                response_tlv = self._handle_command_response(cmd, tlvs)
        else:
            return self._error(f"unknown message: no UUID or COMMAND TLV")

        if request_was_encrypted:
            encrypted_response = self.encrypt(response_tlv)
        else:
            encrypted_response = response_tlv

        resp_with_uuid = self.callback_uuid.encode("utf-8") + encrypted_response
        return base64.b64encode(resp_with_uuid)

    def _handle_checkin(self, tlvs):
        """Process checkin, return callback UUID."""
        agent_uuid = tlvs[TLV_TYPE_UUID].decode("utf-8")
        checkin_info = {"uuid": agent_uuid}

        if TLV_TYPE_DATA in tlvs:
            try:
                checkin_info.update(json.loads(tlvs[TLV_TYPE_DATA]))
            except json.JSONDecodeError:
                pass

        self._log("CHECKIN", json.dumps(checkin_info, indent=2))

        with self.lock:
            self.checked_in = True
            self.checkin_data = checkin_info

        response = pack_tlv(TLV_TYPE_UUID, self.callback_uuid)
        response += pack_tlv(TLV_TYPE_STATUS, "success")
        return response

    def _handle_get_tasking(self, tlvs):
        """Return queued tasks as TLV."""
        self._log("GET_TASKING", "agent requesting tasks")

        if TLV_TYPE_DATA in tlvs:
            try:
                piggybacked = json.loads(tlvs[TLV_TYPE_DATA])
                if isinstance(piggybacked, list):
                    with self.lock:
                        for rsp in piggybacked:
                            self.responses.append(rsp)
                            self._log("RESPONSE", json.dumps(rsp, indent=2))
            except json.JSONDecodeError:
                pass

        with self.lock:
            tasks = list(self.task_queue)
            self.task_queue.clear()

        self._log("TASKING", f"sending {len(tasks)} tasks")

        tasks_json = json.dumps(tasks).encode("utf-8")
        response = pack_tlv(TLV_TYPE_COMMAND, "get_tasking")
        response += pack_tlv(TLV_TYPE_DATA, tasks_json)
        return response

    def _handle_post_response(self, tlvs):
        """Process a standalone post_response."""
        msg = {}
        if TLV_TYPE_TASKID in tlvs:
            msg["task_id"] = tlvs[TLV_TYPE_TASKID].decode("utf-8")

        if TLV_TYPE_OUTPUT in tlvs:
            msg["user_output"] = tlvs[TLV_TYPE_OUTPUT].decode("utf-8", errors="replace")

        if TLV_TYPE_ERROR in tlvs:
            msg["user_output"] = tlvs[TLV_TYPE_ERROR].decode("utf-8", errors="replace")
            msg["status"] = "error"

        if TLV_TYPE_STATUS in tlvs:
            msg["status"] = tlvs[TLV_TYPE_STATUS].decode("utf-8")

        if TLV_TYPE_DATA in tlvs:
            try:
                msg["data"] = json.loads(tlvs[TLV_TYPE_DATA])
            except json.JSONDecodeError:
                msg["data"] = base64.b64encode(tlvs[TLV_TYPE_DATA]).decode()

        if TLV_TYPE_FILEID in tlvs:
            msg["file_id"] = tlvs[TLV_TYPE_FILEID].decode("utf-8")

        if TLV_TYPE_FILEDATA in tlvs:
            msg["file_data"] = base64.b64encode(tlvs[TLV_TYPE_FILEDATA]).decode()

        self._log("POST_RESPONSE", json.dumps(msg, indent=2))

        with self.lock:
            self.responses.append(msg)

        response = pack_tlv(TLV_TYPE_COMMAND, "get_tasking")
        response += pack_tlv(TLV_TYPE_DATA, b"[]")
        return response

    def _handle_command_response(self, cmd, tlvs):
        """Handle a direct command response from agent."""
        msg = {"command": cmd}
        if TLV_TYPE_TASKID in tlvs:
            msg["task_id"] = tlvs[TLV_TYPE_TASKID].decode("utf-8")
        if TLV_TYPE_OUTPUT in tlvs:
            msg["user_output"] = tlvs[TLV_TYPE_OUTPUT].decode("utf-8", errors="replace")
        if TLV_TYPE_ERROR in tlvs:
            msg["user_output"] = tlvs[TLV_TYPE_ERROR].decode("utf-8", errors="replace")
            msg["status"] = "error"
        if TLV_TYPE_DATA in tlvs:
            try:
                msg["data"] = json.loads(tlvs[TLV_TYPE_DATA])
            except json.JSONDecodeError:
                msg["data"] = base64.b64encode(tlvs[TLV_TYPE_DATA]).decode()

        self._log("CMD_RESPONSE", json.dumps(msg, indent=2))
        with self.lock:
            self.responses.append(msg)

        response = pack_tlv(TLV_TYPE_STATUS, "success")
        return response

    def _error(self, msg):
        self._log("ERROR", msg)
        return b"error"

    def _log(self, tag, msg):
        entry = f"[{tag}] {msg}"
        with self.lock:
            self.exchange_log.append(entry)
        print(entry)


class MockMythicHandler(BaseHTTPRequestHandler):
    """HTTP handler for mock Mythic server."""

    server_state: MockMythicState = None

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)

        response = self.server_state.process_message(body)

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        if isinstance(response, bytes):
            self.wfile.write(response)
        else:
            self.wfile.write(str(response).encode())

    def do_GET(self):
        if self.path == "/status":
            status = {
                "checked_in": self.server_state.checked_in,
                "responses_count": len(self.server_state.responses),
                "task_queue_count": len(self.server_state.task_queue),
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(status).encode())
            return

        if self.path.startswith("/queue/"):
            cmd = self.path.split("/queue/")[1].split("?")[0]
            params_str = self.path.split("?params=")[1] if "?params=" in self.path else "{}"
            try:
                params = json.loads(params_str)
            except Exception:
                params = {}
            task_uuid = self.server_state.queue_task(cmd, params)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"task_id": task_uuid}).encode())
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def create_server(port=8080, aes_key=DEFAULT_AES_KEY, uuid=DEFAULT_UUID):
    """Create and return a mock Mythic server."""
    state = MockMythicState(uuid, aes_key)
    MockMythicHandler.server_state = state
    server = HTTPServer(("127.0.0.1", port), MockMythicHandler)
    return server, state


def run_server(port=8080, aes_key=DEFAULT_AES_KEY, uuid=DEFAULT_UUID):
    """Run mock server (blocking)."""
    server, state = create_server(port, aes_key, uuid)
    print(f"Mock Mythic Server listening on http://127.0.0.1:{port}")
    print(f"Payload UUID: {uuid}")
    print(f"AES Key: {aes_key.hex()}")
    print(f"Callback UUID: {CALLBACK_UUID}")
    if not HAS_CRYPTO:
        print("WARNING: pycryptodome not installed - running without encryption")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock Mythic Server for EmeraldStrike")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--aes-key", default=DEFAULT_AES_KEY.hex())
    parser.add_argument("--uuid", default=DEFAULT_UUID)
    args = parser.parse_args()

    aes_key = bytes.fromhex(args.aes_key)
    run_server(args.port, aes_key, args.uuid)
