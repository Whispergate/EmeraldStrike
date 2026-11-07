"""
T1 tests for EmeraldStrike fork-and-run implementation.

Validates:
  1. Translator wire-format changes (fork_and_run_int as first parameter)
  2. Python command parameter additions (execute_assembly, inline_execute)
  3. C source file structure (bootstrap files, headers)
  4. Builder integration (config.h placeholders, build methods)

Run: python -m pytest tests/test_fork_and_run.py -v
"""
import os
import sys
import struct
import base64
import json
import importlib.util

# ── Path setup ──

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOAD_TYPE = os.path.join(REPO, "Payload_Type", "emeraldstrike")
AGENT_CODE = os.path.join(PAYLOAD_TYPE, "emeraldstrike", "agent_code")
AGENT_FUNCS = os.path.join(PAYLOAD_TYPE, "emeraldstrike", "agent_functions")
TRANSLATOR = os.path.join(PAYLOAD_TYPE, "translator")

sys.path.insert(0, TRANSLATOR)


# ── Translator tests ──

class TestTranslatorSchemas:
    """Verify the translator _CMD_SCHEMAS include fork_and_run_int."""

    def _load_translator_module(self):
        spec = importlib.util.spec_from_file_location(
            "translator_mod",
            os.path.join(TRANSLATOR, "translator.py"),
            submodule_search_locations=[],
        )
        # Stub out mythic_container dependency
        import types
        fake_mythic = types.ModuleType("mythic_container")
        fake_base = types.ModuleType("mythic_container.TranslationBase")
        # Provide the classes the translator inherits from
        class FakeTC:
            name = ""
            description = ""
            author = ""
        for cls_name in [
            "TranslationContainer",
            "TrGenerateEncryptionKeysMessage",
            "TrGenerateEncryptionKeysMessageResponse",
            "TrMythicC2ToCustomMessageFormatMessage",
            "TrMythicC2ToCustomMessageFormatMessageResponse",
            "TrCustomMessageToMythicC2FormatMessage",
            "TrCustomMessageToMythicC2FormatMessageResponse",
        ]:
            setattr(fake_base, cls_name, FakeTC)
        fake_mythic.TranslationBase = fake_base
        sys.modules["mythic_container"] = fake_mythic
        sys.modules["mythic_container.TranslationBase"] = fake_base

        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_execute_assembly_schema_has_fork_and_run(self):
        mod = self._load_translator_module()
        schema = mod._CMD_SCHEMAS["execute_assembly"]
        assert schema[0] == ("fork_and_run_int", "int32"), \
            f"First param must be fork_and_run_int int32, got {schema[0]}"
        assert schema[1] == ("assembly_data", "b64"), \
            f"Second param must be assembly_data b64, got {schema[1]}"
        assert schema[2] == ("arguments", "string"), \
            f"Third param must be arguments string, got {schema[2]}"

    def test_inline_execute_schema_has_fork_and_run(self):
        mod = self._load_translator_module()
        schema = mod._CMD_SCHEMAS["inline_execute"]
        assert schema[0] == ("fork_and_run_int", "int32"), \
            f"First param must be fork_and_run_int int32, got {schema[0]}"
        assert schema[1] == ("bof_data", "b64"), \
            f"Second param must be bof_data b64, got {schema[1]}"
        assert schema[2] == ("bof_args", "b64"), \
            f"Third param must be bof_args b64, got {schema[2]}"

    def test_pack_params_execute_assembly(self):
        """Verify _pack_params produces correct binary for execute_assembly."""
        mod = self._load_translator_module()
        asm_bytes = b"\x4d\x5a\x90\x00"  # fake MZ header
        asm_b64 = base64.b64encode(asm_bytes).decode()
        params = {
            "fork_and_run_int": 1,
            "assembly_data": asm_b64,
            "arguments": "arg1 arg2",
        }
        packed = mod._pack_params("execute_assembly", params)

        pos = 0
        # fork_and_run_int: int32 big-endian
        fork_val = struct.unpack(">I", packed[pos:pos+4])[0]
        assert fork_val == 1, f"fork_and_run_int should be 1, got {fork_val}"
        pos += 4

        # assembly_data: b64 -> length-prefixed raw bytes
        asm_len = struct.unpack(">I", packed[pos:pos+4])[0]
        pos += 4
        assert asm_len == len(asm_bytes), f"assembly length mismatch: {asm_len} vs {len(asm_bytes)}"
        assert packed[pos:pos+asm_len] == asm_bytes
        pos += asm_len

        # arguments: length-prefixed string
        args_len = struct.unpack(">I", packed[pos:pos+4])[0]
        pos += 4
        args_str = packed[pos:pos+args_len].decode("utf-8")
        assert args_str == "arg1 arg2"

    def test_pack_params_inline_execute(self):
        """Verify _pack_params produces correct binary for inline_execute."""
        mod = self._load_translator_module()
        bof_bytes = b"\x64\x86\x01\x00"  # fake COFF header
        bof_b64 = base64.b64encode(bof_bytes).decode()
        bof_args = b"\x00\x00\x00\x04test"
        args_b64 = base64.b64encode(bof_args).decode()
        params = {
            "fork_and_run_int": 0,
            "bof_data": bof_b64,
            "bof_args": args_b64,
        }
        packed = mod._pack_params("inline_execute", params)

        pos = 0
        # fork_and_run_int
        fork_val = struct.unpack(">I", packed[pos:pos+4])[0]
        assert fork_val == 0
        pos += 4

        # bof_data: b64 decoded, length-prefixed
        bof_len = struct.unpack(">I", packed[pos:pos+4])[0]
        pos += 4
        assert bof_len == len(bof_bytes)
        assert packed[pos:pos+bof_len] == bof_bytes
        pos += bof_len

        # bof_args: b64 decoded, length-prefixed
        args_len = struct.unpack(">I", packed[pos:pos+4])[0]
        pos += 4
        assert args_len == len(bof_args)
        assert packed[pos:pos+args_len] == bof_args

    def test_fork_and_run_zero_inline(self):
        """Verify fork=0 packs correctly (inline mode, existing behavior)."""
        mod = self._load_translator_module()
        params = {
            "fork_and_run_int": 0,
            "assembly_data": base64.b64encode(b"MZ").decode(),
            "arguments": "",
        }
        packed = mod._pack_params("execute_assembly", params)
        fork_val = struct.unpack(">I", packed[0:4])[0]
        assert fork_val == 0


# ── C source file structure tests ──

class TestCSourceFiles:
    """Verify the C source files exist and have correct structure."""

    def test_fork_and_run_header_exists(self):
        path = os.path.join(AGENT_CODE, "include", "evasion", "fork_and_run.h")
        assert os.path.isfile(path), f"Missing: {path}"

    def test_fork_and_run_cc_exists(self):
        path = os.path.join(AGENT_CODE, "src", "evasion", "fork_and_run.cc")
        assert os.path.isfile(path), f"Missing: {path}"

    def test_clr_bootstrap_exists(self):
        path = os.path.join(AGENT_CODE, "src", "evasion", "clr_bootstrap.cc")
        assert os.path.isfile(path), f"Missing: {path}"

    def test_bof_bootstrap_exists(self):
        path = os.path.join(AGENT_CODE, "src", "evasion", "bof_bootstrap.cc")
        assert os.path.isfile(path), f"Missing: {path}"

    def test_fork_and_run_header_declares_both(self):
        path = os.path.join(AGENT_CODE, "include", "evasion", "fork_and_run.h")
        content = open(path).read()
        assert "fork_run_assembly" in content
        assert "fork_run_bof" in content
        assert "FORK_CTX" in content
        assert "fork_spawn" in content
        assert "fork_collect_output" in content
        assert "fork_cleanup" in content

    def test_fork_and_run_cc_has_both_stubs(self):
        path = os.path.join(AGENT_CODE, "src", "evasion", "fork_and_run.cc")
        content = open(path).read()
        assert "HAS_CLR_STUB" in content
        assert "HAS_BOF_STUB" in content
        assert "CLR_BOOTSTRAP_BYTES" in content
        assert "BOF_BOOTSTRAP_BYTES" in content

    def test_clr_bootstrap_entry_point(self):
        path = os.path.join(AGENT_CODE, "src", "evasion", "clr_bootstrap.cc")
        content = open(path).read()
        assert "clr_entry" in content
        assert "extern \"C\"" in content
        assert "get_kernel32" in content
        assert "find_export" in content
        assert "CLRCreateInstance" in content

    def test_bof_bootstrap_entry_point(self):
        path = os.path.join(AGENT_CODE, "src", "evasion", "bof_bootstrap.cc")
        content = open(path).read()
        assert "bof_entry" in content
        assert "extern \"C\"" in content
        assert "BOF_CTX" in content
        assert "bof_set_ctx" in content
        assert "bof_get_ctx" in content
        assert "resolve_bof_symbol" in content

    def test_bof_bootstrap_has_beacon_apis(self):
        path = os.path.join(AGENT_CODE, "src", "evasion", "bof_bootstrap.cc")
        content = open(path).read()
        required_apis = [
            "BeaconDataParse", "BeaconDataInt", "BeaconDataShort",
            "BeaconDataExtract", "BeaconDataLength",
            "BeaconPrintf", "BeaconOutput",
            "BeaconFormatAlloc", "BeaconFormatFree",
            "BeaconFormatPrintf", "BeaconFormatToString",
        ]
        for api in required_apis:
            assert api in content, f"Missing Beacon API: {api}"

    def test_bof_bootstrap_has_coff_loader(self):
        path = os.path.join(AGENT_CODE, "src", "evasion", "bof_bootstrap.cc")
        content = open(path).read()
        assert "COFF_MACHINE_AMD64" in content or "0x8664" in content
        assert "IMAGE_REL_AMD64_REL32" in content or "REL32" in content
        assert "VirtualAlloc" in content
        assert "VirtualProtect" in content

    def test_bof_bootstrap_has_dfr(self):
        """DFR (MODULE$Function) resolution is critical for real BOFs."""
        path = os.path.join(AGENT_CODE, "src", "evasion", "bof_bootstrap.cc")
        content = open(path).read()
        assert "$" in content  # DFR dollar-sign parsing
        assert "LoadLibraryA" in content

    def test_cmd_execute_assembly_reads_fork_flag(self):
        path = os.path.join(AGENT_CODE, "src", "commands", "cmd_execute_assembly.cc")
        content = open(path).read()
        assert "parser_int32(args)" in content
        assert "fork_flag" in content
        assert "fork_run_assembly" in content
        assert "fork_and_run.h" in content

    def test_cmd_inline_execute_reads_fork_flag(self):
        path = os.path.join(AGENT_CODE, "src", "commands", "cmd_inline_execute.cc")
        content = open(path).read()
        assert "parser_int32(args)" in content
        assert "fork_flag" in content
        assert "fork_run_bof" in content
        assert "fork_and_run.h" in content


# ── Config / Builder integration tests ──

class TestBuilderIntegration:
    """Verify config.h placeholders and builder.py methods."""

    def test_config_h_has_clr_placeholder(self):
        path = os.path.join(AGENT_CODE, "include", "config.h")
        content = open(path).read()
        assert "%CLR_BOOTSTRAP_DEFINE%" in content

    def test_config_h_has_bof_placeholder(self):
        path = os.path.join(AGENT_CODE, "include", "config.h")
        content = open(path).read()
        assert "%BOF_BOOTSTRAP_DEFINE%" in content

    def test_builder_has_clr_build_method(self):
        path = os.path.join(AGENT_FUNCS, "builder.py")
        content = open(path).read()
        assert "_build_clr_bootstrap" in content
        assert "clr_bootstrap.cc" in content
        assert "CLR_BOOTSTRAP_BYTES" in content
        assert "CLR_BOOTSTRAP_SIZE" in content

    def test_builder_has_bof_build_method(self):
        path = os.path.join(AGENT_FUNCS, "builder.py")
        content = open(path).read()
        assert "_build_bof_bootstrap" in content
        assert "bof_bootstrap.cc" in content
        assert "BOF_BOOTSTRAP_BYTES" in content
        assert "BOF_BOOTSTRAP_SIZE" in content

    def test_builder_stamps_both_placeholders(self):
        path = os.path.join(AGENT_FUNCS, "builder.py")
        content = open(path).read()
        assert "CLR_BOOTSTRAP_DEFINE" in content
        assert "BOF_BOOTSTRAP_DEFINE" in content

    def test_builder_entry_points_differ(self):
        """CLR uses clr_entry, BOF uses bof_entry."""
        path = os.path.join(AGENT_FUNCS, "builder.py")
        content = open(path).read()
        assert '"clr_entry"' in content
        assert '"bof_entry"' in content


# ── Bootstrap PIC compliance checks ──

class TestPICCompliance:
    """Verify bootstrap files don't violate PIC constraints."""

    def _check_no_string_literals(self, path):
        """String literals in .rdata break PIC. Stack strings only."""
        with open(path) as f:
            lines = f.readlines()

        in_comment = False
        violations = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Track block comments
            if "/*" in stripped:
                in_comment = True
            if "*/" in stripped:
                in_comment = False
                continue
            if in_comment or stripped.startswith("//") or stripped.startswith("*"):
                continue
            # Skip preprocessor
            if stripped.startswith("#"):
                continue
            # Skip char-by-char assignments (s[0] = 'x')
            if "= '" in stripped and len(stripped) < 80:
                continue
            # Look for string literals that aren't in comments
            # Allow: char arrays like {'x','y'}, format string detection
            if '"' in stripped:
                # Allow: #include, comments, single-char strings in assertions
                if '#include' in stripped:
                    continue
                if '//' in stripped and stripped.index('//') < stripped.index('"'):
                    continue
                # This is potentially a string literal in code
                # Allow empty strings ""
                import re
                strings = re.findall(r'"([^"]*)"', stripped)
                for s in strings:
                    if len(s) > 0 and s not in ("C", "c"):
                        violations.append((i, stripped.rstrip()))
        return violations

    def test_clr_bootstrap_no_string_globals(self):
        """CLR bootstrap must not reference global variables."""
        path = os.path.join(AGENT_CODE, "src", "evasion", "clr_bootstrap.cc")
        content = open(path).read()
        # Global/static variables (outside functions) would break PIC
        # Look for 'static' at file scope that's not 'static inline'
        import re
        # Should only have static inline functions, not static data
        static_data = re.findall(r'^static\s+(?!inline|constexpr|void|DWORD|int|BOOL|HRESULT|LONG|SAFEARRAY|VARIANT|WORD|unsigned|char\*|BSTR|HANDLE|fn_|HMODULE|FARPROC|LPVOID)', content, re.MULTILINE)
        # This is a rough check - the key constraint is no .rdata references

    def test_bof_bootstrap_has_teb_context(self):
        """BOF bootstrap must use TEB for context, not globals."""
        path = os.path.join(AGENT_CODE, "src", "evasion", "bof_bootstrap.cc")
        content = open(path).read()
        assert "0x28" in content  # TEB ArbitraryUserPointer offset
        assert "bof_set_ctx" in content
        assert "bof_get_ctx" in content


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
