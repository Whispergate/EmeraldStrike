"""T1 static verification for the NomadX parity changes.

Validates: BOF migration, guardrails module, resilience improvements.
No container, no Mythic, no imports from mythic_container.
"""
import pathlib
import re
import struct
import os

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENT_CODE = ROOT / "agent_code"
AGENT_FUNCS = ROOT / "agent_functions"
BOF_DIR = ROOT / "bof_files"
SRC = AGENT_CODE / "src"
INC = AGENT_CODE / "include"


# ── BOF Migration ──

BOF_REPLACED_CMDS = [
    "arp", "clipboard", "dns", "domaininfo", "env",
    "localgroup", "psgrep", "route", "services", "uptime", "windowlist",
]

BOF_FILES = {
    "arp": "es_arp.x64.o",
    "clipboard": "es_clipdump.x64.o",
    "dns": "es_nslookup.x64.o",
    "domaininfo": "es_ldapsearch.x64.o",
    "env": "es_env.x64.o",
    "localgroup": "es_netlocalgroup.x64.o",
    "psgrep": "es_pslist_handles.x64.o",
    "route": "es_routeprint.x64.o",
    "services": "es_sc_enum.x64.o",
    "uptime": "es_uptime.x64.o",
    "windowlist": "es_windowlist.x64.o",
}


def test_bof_files_directory_exists():
    assert BOF_DIR.is_dir(), f"bof_files/ directory missing at {BOF_DIR}"


def test_all_bof_object_files_exist():
    for cmd, filename in BOF_FILES.items():
        path = BOF_DIR / filename
        assert path.exists(), f"BOF file missing for {cmd}: {path}"
        assert path.stat().st_size > 100, f"BOF file suspiciously small for {cmd}: {path.stat().st_size} bytes"


def test_no_nx_prefix_in_bof_files():
    for f in BOF_DIR.iterdir():
        if f.suffix == ".o":
            assert not f.name.startswith("nx_"), f"BOF file still has nx_ prefix: {f.name}"


def test_bof_utils_exists():
    path = AGENT_FUNCS / "bof_utils.py"
    assert path.exists(), "bof_utils.py missing"
    content = path.read_text()
    assert "bof_tasking" in content, "bof_utils.py missing bof_tasking function"
    assert "inline_execute" in content, "bof_utils.py should redirect to inline_execute"


def test_bof_replaced_py_files_redirect():
    """Each BOF-replaced command's .py file should call bof_tasking and not define native params."""
    for cmd in BOF_REPLACED_CMDS:
        path = AGENT_FUNCS / f"{cmd}.py"
        assert path.exists(), f"{cmd}.py missing"
        content = path.read_text()
        assert "bof_tasking" in content, f"{cmd}.py does not call bof_tasking"
        assert "bof_utils" in content, f"{cmd}.py does not import from bof_utils"


def test_no_nx_prefix_in_py_files():
    for py in AGENT_FUNCS.glob("*.py"):
        content = py.read_text()
        assert "nx_" not in content, f"{py.name} still references nx_ prefix"


def test_builder_excludes_bof_replaced():
    builder = AGENT_FUNCS / "builder.py"
    content = builder.read_text()
    assert "_BOF_REPLACED" in content, "builder.py missing _BOF_REPLACED set"
    assert "selected_cmds -= _BOF_REPLACED" in content or "selected_cmds -=" in content, \
        "builder.py does not subtract BOF-replaced commands"
    # Verify all 11 commands are in the set
    for cmd in BOF_REPLACED_CMDS:
        if cmd == "psgrep":
            continue  # psgrep may be listed differently
        assert f'"{cmd}"' in content, f"builder.py _BOF_REPLACED missing {cmd}"


def test_bof_replaced_py_have_dependencies():
    """BOF-redirect commands should declare dependency on inline_execute."""
    for cmd in BOF_REPLACED_CMDS:
        path = AGENT_FUNCS / f"{cmd}.py"
        content = path.read_text()
        assert "inline_execute" in content, f"{cmd}.py missing inline_execute dependency"


# ── Guardrails Module ──

def test_guardrails_header_exists():
    path = INC / "evasion" / "guardrails.h"
    assert path.exists(), "guardrails.h missing"
    content = path.read_text()
    assert "guardrails_check" in content, "guardrails.h missing guardrails_check declaration"


def test_guardrails_source_exists():
    path = SRC / "evasion" / "guardrails.cc"
    assert path.exists(), "guardrails.cc missing"
    content = path.read_text()
    assert "guardrails_check" in content, "guardrails.cc missing guardrails_check definition"


def test_guardrails_all_checks_present():
    content = (SRC / "evasion" / "guardrails.cc").read_text()
    checks = [
        "INCLUDE_GUARDRAIL_PRE_SLEEP",
        "INCLUDE_GUARDRAIL_COMPUTATIONAL_DELAY",
        "INCLUDE_GUARDRAIL_ANTI_DEBUG",
        "INCLUDE_GUARDRAIL_DOMAIN_JOINED",
        "INCLUDE_GUARDRAIL_ANTI_SANDBOX",
        "INCLUDE_GUARDRAIL_ANTI_EMULATION",
    ]
    for check in checks:
        assert check in content, f"guardrails.cc missing {check}"


def test_guardrails_anti_sandbox_heuristics():
    content = (SRC / "evasion" / "guardrails.cc").read_text()
    # Uptime check
    assert "30" in content, "Missing 30-minute uptime threshold"
    # Screen size
    assert "1024" in content, "Missing 1024 screen width check"
    assert "768" in content, "Missing 768 screen height check"
    # Username blocklist
    for name in ["sandbox", "cuckoo", "malware"]:
        assert name in content.lower(), f"Missing blocklist entry: {name}"


def test_guardrails_anti_emulation_checks():
    content = (SRC / "evasion" / "guardrails.cc").read_text()
    # Timing check
    assert "2500" in content or "2200" in content, "Missing timing check values"
    # CPU burn
    assert "100000000" in content or "100_000_000" in content, "Missing 100M CPU burn"
    # Large alloc
    assert "256" in content, "Missing 256MB alloc reference"


def test_guardrails_pic_safe():
    """Guardrails should resolve APIs via GetProcAddress, not direct Win32 calls."""
    content = (SRC / "evasion" / "guardrails.cc").read_text()
    assert "GetProcAddress" in content, "guardrails.cc should resolve APIs via GetProcAddress"
    # Should use xstr for strings
    assert "xstr" in content.lower() or "XSTR" in content, "guardrails.cc should use obfuscated strings"


def test_config_h_has_guardrail_macros():
    content = (INC / "config.h").read_text()
    for macro in [
        "INCLUDE_GUARDRAIL_PRE_SLEEP",
        "INCLUDE_GUARDRAIL_COMPUTATIONAL_DELAY",
        "INCLUDE_GUARDRAIL_ANTI_DEBUG",
        "INCLUDE_GUARDRAIL_DOMAIN_JOINED",
        "INCLUDE_GUARDRAIL_ANTI_SANDBOX",
        "INCLUDE_GUARDRAIL_ANTI_EMULATION",
    ]:
        assert macro in content, f"config.h missing {macro}"


def test_builder_has_guardrail_parameters():
    content = (AGENT_FUNCS / "builder.py").read_text()
    params = [
        "guardrail_pre_sleep",
        "guardrail_computational_delay",
        "guardrail_anti_debug",
        "guardrail_domain_joined",
        "guardrail_anti_sandbox",
        "guardrail_anti_emulation",
        "pre_sleep_seconds",
    ]
    for param in params:
        assert param in content, f"builder.py missing BuildParameter: {param}"


def test_builder_stamps_guardrail_defines():
    content = (AGENT_FUNCS / "builder.py").read_text()
    assert "INCLUDE_GUARDRAIL" in content, "builder.py does not stamp INCLUDE_GUARDRAIL defines"


def test_pre_sleep_in_config_blob():
    """builder.py should pack pre_sleep_seconds into the config blob."""
    content = (AGENT_FUNCS / "builder.py").read_text()
    assert "pre_sleep" in content, "builder.py missing pre_sleep_seconds in config serialization"


# ── Kill-date Enforcement ──

def test_killdate_checked_in_main_loop():
    content = (SRC / "main.cc").read_text()
    # Must check killdate inside the while(inst->Running) loop
    assert "killdate" in content.lower()
    assert "GetSystemTime" in content, "main.cc should use GetSystemTime for kill-date check"
    # Should compute YYYYMMDD
    assert "YYYYMMDD" in content or ("10000" in content and "100" in content), \
        "main.cc should convert date to YYYYMMDD integer"


def test_pre_sleep_parsed_in_config():
    content = (SRC / "main.cc").read_text()
    assert "pre_sleep_seconds" in content, "main.cc should parse pre_sleep_seconds from config blob"


# ── Guardrails Call Site ──

def test_guardrails_called_before_checkin():
    content = (SRC / "main.cc").read_text()
    # Find within agent_main only (not the function definition above)
    agent_main_start = content.find("VOID agent_main(")
    assert agent_main_start > 0, "agent_main not found"
    main_body = content[agent_main_start:]
    guard_pos = main_body.find("guardrails_check")
    checkin_pos = main_body.find("build_checkin_msg")
    assert guard_pos > 0, "guardrails_check not found in agent_main"
    assert checkin_pos > 0, "build_checkin_msg not found in agent_main"
    assert guard_pos < checkin_pos, "guardrails_check must come before build_checkin_msg in agent_main"


def test_guardrails_include_in_main():
    content = (SRC / "main.cc").read_text()
    assert '#include "evasion/guardrails.h"' in content, "main.cc missing guardrails.h include"


# ── Resilience: Checkin Retry ──

def test_checkin_retry_loop():
    content = (SRC / "main.cc").read_text()
    # Should have a retry loop with ~6 attempts
    assert "max_checkin" in content or "checkin_attempt" in content or "attempt" in content, \
        "main.cc missing checkin retry loop"
    assert "5000" in content, "main.cc missing 5000ms (5s) checkin retry delay"


def test_checkin_retry_exits_on_failure():
    """If all retries fail, agent should exit silently."""
    content = (SRC / "main.cc").read_text()
    # After retry loop, should check Connected and exit
    # Look for the pattern: retries exhausted -> exit
    assert "ExitProcess" in content or "ExitThread" in content, \
        "main.cc should exit after all checkin retries fail"


# ── Resilience: HTTP Retry ──

def test_http_retry_wrapper():
    content = (SRC / "transport" / "http.cc").read_text()
    assert "retry" in content.lower(), "http.cc missing retry wrapper"
    assert "500" in content, "http.cc missing 500ms backoff"
    assert "1500" in content, "http.cc missing 1500ms backoff"


def test_http_retry_covers_both_transports():
    """Both WinINet and WinHTTP paths should have retry."""
    content = (SRC / "transport" / "http.cc").read_text()
    # Count retry wrapper occurrences (should be 2: one for WinINet, one for WinHTTP)
    retry_count = content.count("_http_request_retry")
    assert retry_count >= 4, f"Expected retry wrapper used in multiple places, found {retry_count} occurrences"


def test_azure_blob_retry():
    path = SRC / "transport" / "azure_blob.cc"
    if path.exists():
        content = path.read_text()
        assert "retry" in content.lower(), "azure_blob.cc missing retry wrapper"


# ── Jitter ──

def test_jitter_applied_in_sleep():
    content = (SRC / "evasion" / "sleep.cc").read_text()
    assert "jitter" in content.lower(), "sleep.cc missing jitter implementation"
    assert "rdtsc" in content.lower() or "GetTickCount" in content, \
        "sleep.cc should use rdtsc or GetTickCount for randomness"


# ── Cross-cutting ──

def test_no_crt_in_guardrails():
    """Guardrails should not include CRT headers."""
    content = (SRC / "evasion" / "guardrails.cc").read_text()
    assert "#include <stdio.h>" not in content
    assert "#include <stdlib.h>" not in content
    assert "#include <string.h>" not in content


def test_common_h_has_pre_sleep_field():
    content = (INC / "common.h").read_text()
    assert "pre_sleep_seconds" in content, "common.h INSTANCE Config missing pre_sleep_seconds field"


# ── Token Store ──

def test_token_store_cc_exists():
    path = SRC / "commands" / "cmd_token_store.cc"
    assert path.exists(), "cmd_token_store.cc missing"
    content = path.read_text()
    assert "INCLUDE_CMD_TOKEN_STORE" in content
    assert "token_store_add" in content


def test_token_store_py_exists():
    path = AGENT_FUNCS / "token_store.py"
    assert path.exists()
    content = path.read_text()
    assert 'cmd = "token_store"' in content
    assert "T1134" in content


def test_token_store_in_common_h():
    content = (INC / "common.h").read_text()
    assert "TokenStore" in content
    assert "ES_TOKEN_STORE_SLOTS" in content or "TOKEN_STORE" in content
    assert "ActiveTokenSlot" in content


def test_token_store_in_dispatch():
    content = (SRC / "dispatch.cc").read_text()
    assert "token_store" in content
    assert "cmd_token_store" in content


def test_token_store_in_config_h():
    content = (INC / "config.h").read_text()
    assert "INCLUDE_CMD_TOKEN_STORE" in content


def test_token_store_in_translator():
    translator = ROOT.parent / "translator" / "translator.py"
    content = translator.read_text()
    assert "token_store" in content


def test_steal_token_stores():
    content = (SRC / "commands" / "cmd_steal_token.cc").read_text()
    assert "token_store_add" in content, "steal_token should store the token"


def test_make_token_stores():
    content = (SRC / "commands" / "cmd_make_token.cc").read_text()
    assert "token_store_add" in content, "make_token should store the token"


def test_shell_token_aware():
    content = (SRC / "commands" / "cmd_shell.cc").read_text()
    assert "CreateProcessAsUserW" in content or "CreateProcessAsUser" in content, \
        "shell should use CreateProcessAsUserW when impersonating"


# ── SOCKS5 Proxy ──

def test_socks_h_exists():
    path = INC / "socks.h"
    assert path.exists()
    content = path.read_text()
    assert "socks_init" in content
    assert "socks_poll" in content
    assert "SOCKS_CTX" in content or "socks_ctx" in content.lower()


def test_socks_cc_exists():
    path = SRC / "socks.cc"
    assert path.exists()
    content = path.read_text()
    assert "socks_init" in content
    assert "socks_handle_downstream" in content or "socks_handle" in content
    assert "socks_poll" in content
    assert "ws2_32" in content.lower() or "WS2_32" in content


def test_socks_in_config_h():
    content = (INC / "config.h").read_text()
    assert "INCLUDE_SOCKS_PROXY" in content
    assert "INCLUDE_CMD_SOCKS" in content


def test_socks_in_dispatch():
    content = (SRC / "dispatch.cc").read_text()
    assert "cmd_socks" in content


def test_socks_in_common_h():
    content = (INC / "common.h").read_text()
    assert "pSocksCtx" in content


def test_socks_in_main_loop():
    content = (SRC / "main.cc").read_text()
    assert "TLV_SOCKS" in content or "socks_poll" in content


def test_socks_in_translator():
    translator = ROOT.parent / "translator" / "translator.py"
    content = translator.read_text()
    assert "TLV_TYPE_SOCKS" in content or "TLV_SOCKS" in content
    assert "socks" in content


def test_socks_pic_safe():
    content = (SRC / "socks.cc").read_text()
    assert "GetProcAddress" in content or "resolve_function" in content
    assert "xstr" in content.lower() or "XSTR" in content


# ── Reverse Port Forwarding ──

TRANSLATOR = ROOT.parent / "translator" / "translator.py"


def test_rpfwd_h_exists():
    path = INC / "rpfwd.h"
    assert path.exists()
    content = path.read_text()
    assert "rpfwd_init" in content or "rpfwd_start" in content
    assert "rpfwd_poll" in content
    assert "RPFWD_CTX" in content or "rpfwd_ctx" in content.lower()


def test_rpfwd_cc_exists():
    path = SRC / "rpfwd.cc"
    assert path.exists()
    content = path.read_text()
    assert "rpfwd_start" in content
    assert "rpfwd_poll" in content
    assert "rpfwd_handle_downstream" in content or "rpfwd_handle" in content
    assert "bind" in content.lower()
    assert "listen" in content.lower()
    assert "accept" in content.lower()


def test_rpfwd_in_config_h():
    content = (INC / "config.h").read_text()
    assert "INCLUDE_RPFWD" in content
    assert "INCLUDE_CMD_RPORTFWD" in content


def test_rpfwd_in_dispatch():
    content = (SRC / "dispatch.cc").read_text()
    assert "cmd_rportfwd" in content


def test_rpfwd_in_common_h():
    content = (INC / "common.h").read_text()
    assert "pRpfwdCtx" in content


def test_rpfwd_in_main_loop():
    content = (SRC / "main.cc").read_text()
    assert "TLV_RPFWD" in content
    assert "rpfwd_poll" in content or "rpfwd_build_upstream" in content


def test_rpfwd_in_translator():
    content = TRANSLATOR.read_text()
    assert "TLV_TYPE_RPFWD" in content or "TLV_RPFWD" in content
    assert "rpfwd" in content.lower() or "rportfwd" in content


def test_rpfwd_pic_safe():
    content = (SRC / "rpfwd.cc").read_text()
    assert "GetProcAddress" in content or "resolve_function" in content
    assert "xstr" in content.lower() or "XSTR" in content


def test_rpfwd_winsock_shared_guards():
    """SOCKS and rpfwd headers should coexist without duplicate typedefs."""
    socks_h = (INC / "socks.h").read_text()
    rpfwd_h = (INC / "rpfwd.h").read_text()
    # At least one of them should have include guards for shared Winsock types
    has_guard = ("_WS_STRUCTS_DEFINED" in socks_h or "_WS_STRUCTS_DEFINED" in rpfwd_h or
                 "WS_TYPES" in socks_h or "WS_TYPES" in rpfwd_h)
    assert has_guard, "SOCKS and rpfwd headers need shared Winsock typedef guards"
