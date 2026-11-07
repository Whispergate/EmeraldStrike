"""T1 tests for the Azure Blob transport wiring."""
import os
import re
import struct

AGENT = os.path.join(os.path.dirname(__file__), "..", "Payload_Type", "emeraldstrike", "emeraldstrike", "agent_code")
BUILDER = os.path.join(os.path.dirname(__file__), "..", "Payload_Type", "emeraldstrike", "emeraldstrike", "agent_functions", "builder.py")


def read(*p):
    with open(os.path.join(*p), "r", encoding="utf-8", errors="replace") as f:
        return f.read()


class TestTransportSource:
    def test_transport_file_exists(self):
        assert os.path.exists(os.path.join(AGENT, "src", "transport", "azure_blob.cc"))

    def test_header_exists(self):
        assert os.path.exists(os.path.join(AGENT, "include", "transport_azure_blob.h"))

    def test_header_declares_post_response(self):
        h = read(AGENT, "include", "transport_azure_blob.h")
        assert "BOOL blob_post_response(PINSTANCE inst, BYTE* data, DWORD data_len," in h

    def test_ats_sta_paths(self):
        src = read(AGENT, "src", "transport", "azure_blob.cc")
        assert '"ats/' in src and '"sta/' in src

    def test_blockblob_header(self):
        src = read(AGENT, "src", "transport", "azure_blob.cc")
        assert "x-ms-blob-type: BlockBlob" in src

    def test_404_tolerance(self):
        # A missing sta blob must be treated as "not ready", not fatal
        src = read(AGENT, "src", "transport", "azure_blob.cc")
        assert "st == 404" in src

    def test_response_poll_capped(self):
        src = read(AGENT, "src", "transport", "azure_blob.cc")
        m = re.search(r"#define BLOB_MAX_POLLS (\d+)", src)
        assert m and int(m.group(1)) > 10

    def test_message_id_is_v4_uuid(self):
        src = read(AGENT, "src", "transport", "azure_blob.cc")
        assert "0x40" in src and "0x80" in src  # version/variant nibbles

    def test_reply_blob_deleted_after_read(self):
        src = read(AGENT, "src", "transport", "azure_blob.cc")
        assert "blob_delete(inst, sta_path)" in src

    def test_both_libraries_supported(self):
        src = read(AGENT, "src", "transport", "azure_blob.cc")
        assert "#ifdef USE_WININET" in src and "#else // USE_WINHTTP" in src

    def test_poll_routes_through_sleep_mask(self):
        src = read(AGENT, "src", "transport", "azure_blob.cc")
        assert "do_sleep(inst, inst->Config.sleep_ms)" in src


class TestMainWiring:
    def setup_method(self):
        self.main = read(AGENT, "src", "main.cc")

    def test_parse_config_blob_branch(self):
        assert "#ifdef AZURE_BLOB_TRANSPORT" in self.main
        assert "inst->Blob.host" in self.main
        assert "inst->Blob.container" in self.main
        assert "inst->Blob.sas" in self.main

    def test_blob_branch_locals_not_shared_with_smb(self):
        # The blob branch must not depend on slen/copylen declared in other
        # transport branches (azure-only builds have neither). Locate the
        # parse_config blob branch specifically (it touches inst->Blob.host).
        main = self.main
        start = main.index("#ifdef AZURE_BLOB_TRANSPORT", main.index("inst->Smb.pipename"))
        blob = main[start:main.index("#endif", start)]
        assert "DWORD bslen, bcopy;" in blob
        assert "inst->Blob.host" in blob

    def test_send_alias(self):
        assert "#define http_post_response blob_post_response" in self.main

    def test_agent_init_loads_wininet_for_blob(self):
        assert "#if defined(HTTP_TRANSPORT) || defined(AZURE_BLOB_TRANSPORT)" in self.main

    def test_main_loop_gates_widened(self):
        assert "#if defined(HTTP_TRANSPORT) || defined(AZURE_BLOB_TRANSPORT)\n    // Initial checkin" in self.main

    def test_httpqueryinfoa_resolved(self):
        assert "H_HTTPQUERYINFOA" in self.main

    def test_instance_has_blob_struct(self):
        common = read(AGENT, "include", "common.h")
        assert "} Blob;" in common

    def test_new_hashes_present(self):
        native = read(AGENT, "include", "native.h")
        assert "#define H_HTTPQUERYINFOA            0x578f84d2" in native
        assert "#define H_WINHTTPQUERYHEADERS       0x7928f3ef" in native


class TestBuilder:
    def setup_method(self):
        self.b = read(BUILDER)

    def test_profile_registered(self):
        assert '"azure_blob"' in self.b

    def test_transport_define(self):
        assert "#define AZURE_BLOB_TRANSPORT" in self.b

    def test_provisioning_rpc(self):
        assert 'ServiceName="azure_blob"' in self.b
        assert 'ServiceRPCFunction="generate_config"' in self.b
        assert '"payload_uuid"' in self.b
        assert '"killdate"' in self.b

    def test_account_key_never_stamped(self):
        # Only endpoint/container/SAS may be serialized; the account key must
        # never leave the C2 profile server.
        assert "account_key" not in self.b

    def test_serialize_matches_parse_order(self):
        assert 'blob_provision["host"]' in self.b
        assert 'blob_provision["container_name"]' in self.b
        assert 'blob_provision["sas_token"]' in self.b

    def test_serialize_signature_takes_provision(self):
        assert "def _serialize_config(self, c2_profile, c2_params, blob_provision=None)" in self.b

    def test_provision_failure_aborts_build(self):
        assert "raise Exception(f\"Azure container provisioning failed" in self.b

    def test_sas_leading_question_mark_stripped(self):
        assert 'lstrip("?")' in self.b

    def test_killdate_fallback_28d(self):
        assert "timedelta(days=28)" in self.b
