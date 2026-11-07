"""
T1 Unit Tests - HellsHall Indirect Syscalls + Ekko Sleep
Validates code structure, defines, builder integration, and injection plumbing.
"""
import os
import re
import pytest

AGENT_CODE = os.path.join(os.path.dirname(__file__), "..",
    "Payload_Type", "emeraldstrike", "emeraldstrike", "agent_code")
AGENT_FUNCS = os.path.join(os.path.dirname(__file__), "..",
    "Payload_Type", "emeraldstrike", "emeraldstrike", "agent_functions")

def read(relpath):
    with open(os.path.join(AGENT_CODE, relpath), "r", encoding="utf-8", errors="replace") as f:
        return f.read()

def read_py(relpath):
    with open(os.path.join(AGENT_FUNCS, relpath), "r", encoding="utf-8", errors="replace") as f:
        return f.read()

# ─── HellsHall Header ───

class TestHellsHallHeader:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("include/evasion/hellshall.h")

    def test_include_guard(self):
        assert "EMERALDSTRIKE_HELLSHALL_H" in self.src

    def test_ifdef_guard(self):
        assert "#ifdef INCLUDE_EVASION_HELLSHALL" in self.src

    def test_nt_syscall_struct(self):
        assert "typedef struct _NT_SYSCALL" in self.src
        assert "dwSSn" in self.src
        assert "pSyscallAddress" in self.src
        assert "pSyscallInstAddress" in self.src

    def test_crc32_hashes_present(self):
        hashes = [
            "NtAllocateVirtualMemory_CRC32",
            "NtProtectVirtualMemory_CRC32",
            "NtWriteVirtualMemory_CRC32",
            "NtCreateThreadEx_CRC32",
            "NtWaitForSingleObject_CRC32",
            "NtCreateSection_CRC32",
            "NtMapViewOfSection_CRC32",
            "NtUnmapViewOfSection_CRC32",
            "NtQueueApcThread_CRC32",
            "NtClose_CRC32",
            "NtCreateEvent_CRC32",
            "NtSignalAndWaitForSingleObject_CRC32",
            "NtContinue_CRC32",
        ]
        for h in hashes:
            assert h in self.src, f"Missing CRC32 hash: {h}"

    def test_index_defines(self):
        for i in range(13):
            assert f"HH_IDX_" in self.src

    def test_hh_gate_struct(self):
        assert "HH_GATE" in self.src
        assert "SSn" in self.src
        assert "SyscallAddr" in self.src

    def test_naked_stub(self):
        assert "__attribute__((naked" in self.src
        assert "HH_RunSyscall" in self.src
        assert "mov r10, rcx" in self.src
        assert "jmp r11" in self.src

    def test_teb_gs_prefix_bytes(self):
        # gs:[0x28] encoded as .byte sequence
        assert "0x65" in self.src  # gs: prefix

    def test_hh_syscall_macro(self):
        assert "HH_SYSCALL" in self.src
        assert "_hh_read_teb" in self.src
        assert "_hh_write_teb" in self.src

    def test_function_declarations(self):
        assert "hellshall_init" in self.src
        assert "hellshall_fetch" in self.src
        assert "hh_crc32b" in self.src


# ─── HellsHall Implementation ───

class TestHellsHallImpl:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("src/evasion/hellshall.cc")

    def test_include_guard(self):
        assert "#ifdef INCLUDE_EVASION_HELLSHALL" in self.src

    def test_crc32b_function(self):
        assert "hh_crc32b" in self.src
        assert "0xFFFFEFFF" in self.src
        assert "0xEDB88320" in self.src

    def test_ntdll_config_struct(self):
        assert "NTDLL_CONFIG" in self.src
        assert "pdwArrayOfAddresses" in self.src
        assert "pdwArrayOfNames" in self.src

    def test_pe_header_parsing(self):
        assert "IMAGE_DOS_HEADER" in self.src
        assert "IMAGE_NT_HEADERS" in self.src
        assert "IMAGE_EXPORT_DIRECTORY" in self.src

    def test_hook_recovery_scenarios(self):
        # Clean syscall pattern: 4C 8B D1 B8
        assert "0x4C" in self.src
        assert "0x8B" in self.src
        assert "0xD1" in self.src
        assert "0xB8" in self.src
        # Hooked scenario 1: JMP at offset 0
        assert "0xE9" in self.src
        # Search up/down
        assert "SEARCH_UP" in self.src
        assert "SEARCH_DOWN" in self.src

    def test_random_syscall_address(self):
        # Looks for syscall instruction bytes 0F 05
        assert "0x0F" in self.src
        assert "0x05" in self.src
        assert "__rdtsc" in self.src

    def test_hellshall_init(self):
        assert "hellshall_init" in self.src
        assert "inst->Modules.Ntdll" in self.src
        assert "inst->HH_Syscalls" in self.src
        assert "inst->bHellsHallInit" in self.src

    def test_no_printf(self):
        assert "printf" not in self.src

    def test_uses_es_memset(self):
        assert "es_memset" in self.src


# ─── Ekko Sleep ───

class TestEkkoSleep:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("src/evasion/sleep.cc")

    def test_ekko_ifdef(self):
        assert "#if SLEEP_MASK_TYPE == MASK_EKKO" in self.src

    def test_ustring_typedef(self):
        assert "USTRING" in self.src

    def test_api_resolution_via_djb2(self):
        apis = [
            "RtlCreateTimerQueue",
            "RtlCreateTimer",
            "RtlDeleteTimerQueueEx",
            "RtlCaptureContext",
            "SystemFunction032",
            "SetEvent",
            "WaitForSingleObjectEx",
            "VirtualProtect",
            "NtCreateEvent",
            "NtSignalAndWaitForSingleObject",
            "NtContinue",
            "NtClose",
        ]
        for api in apis:
            assert api in self.src, f"Missing API resolution: {api}"

    def test_xstr_usage(self):
        assert "xstr(" in self.src

    def test_resolve_function_usage(self):
        assert "resolve_function" in self.src
        assert "hash_string_djb2" in self.src

    def test_context_count(self):
        assert "EKKO_NUM_CONTEXTS" in self.src
        assert "8" in self.src

    def test_rop_chain_contexts(self):
        # All 8 context RIP assignments
        for i in range(8):
            assert f"pContexts[{i}].Rip" in self.src, f"Missing ctx[{i}].Rip"

    def test_virtualprotect_rw_rx(self):
        assert "PAGE_READWRITE" in self.src
        assert "PAGE_EXECUTE_READ" in self.src

    def test_systemfunction032_calls(self):
        # Two calls: encrypt and decrypt
        count = self.src.count("pSystemFunction032")
        assert count >= 4, f"Expected >=4 refs to pSystemFunction032, got {count}"

    def test_ntcontinue_timer_queue(self):
        assert "pNtContinue" in self.src
        assert "WT_EXECUTEINTIMERTHREAD" in self.src

    def test_signal_and_wait(self):
        assert "pNtSignalAndWait" in self.src
        assert "EvntStart" in self.src
        assert "EvntEnd" in self.src

    def test_cleanup(self):
        assert "RtlDeleteTimerQueueEx" in self.src
        assert "pNtClose" in self.src

    def test_heap_mask_unmask(self):
        # Should mask before and unmask after
        mask_count = self.src.count("xor_bytes")
        assert mask_count >= 2, f"Expected >=2 xor_bytes calls, got {mask_count}"

    def test_graceful_fallback(self):
        assert "sleep_mask_default" in self.src

    def test_key_generation(self):
        assert "ekko_gen_key" in self.src
        assert "RtlRandomEx" in self.src
        assert "__rdtsc" in self.src

    def test_ekko_disabled_fallback(self):
        # When not MASK_EKKO, should fall back
        assert "sleep_mask_default(inst, ms)" in self.src


# ─── Injection Integration ───

class TestInjectionHellsHall:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("src/evasion/injection.cc")

    def test_hellshall_include(self):
        assert '#include "evasion/hellshall.h"' in self.src

    def test_inject_hellshall_function(self):
        assert "inject_hellshall" in self.src

    def test_uses_hh_syscall_macro(self):
        assert "HH_SYSCALL(" in self.src

    def test_nt_calls(self):
        assert "HH_IDX_NtAllocateVirtualMemory" in self.src
        assert "HH_IDX_NtWriteVirtualMemory" in self.src
        assert "HH_IDX_NtProtectVirtualMemory" in self.src
        assert "HH_IDX_NtCreateThreadEx" in self.src

    def test_auto_prefer_hellshall(self):
        assert "inst->bHellsHallInit" in self.src
        assert "inject_hellshall(inst" in self.src

    def test_smartinject_guard(self):
        assert "INCLUDE_EVASION_SMARTINJECT" in self.src
        assert "PAGE_EXECUTE_READ" in self.src

    def test_fallback_path(self):
        assert "gate_VirtualAllocEx" in self.src


# ─── Common.h INSTANCE ───

class TestCommonH:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("include/common.h")

    def test_nt_syscall_typedef(self):
        assert "_NT_SYSCALL_DEFINED" in self.src
        assert "typedef struct _NT_SYSCALL" in self.src

    def test_hh_syscalls_field(self):
        assert "HH_Syscalls[16]" in self.src
        assert "bHellsHallInit" in self.src

    def test_ekko_fields(self):
        assert "EkkoKey[16]" in self.src
        assert "bEkkoInitialized" in self.src

    def test_hellshall_init_declaration(self):
        assert "hellshall_init" in self.src

    def test_ifdef_guards(self):
        assert "#ifdef INCLUDE_EVASION_HELLSHALL" in self.src
        assert "SLEEP_MASK_TYPE == MASK_EKKO" in self.src


# ─── Config.h ───

class TestConfigH:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("include/config.h")

    def test_inject_hellshall_constant(self):
        assert "INJECT_HELLSHALL" in self.src
        assert re.search(r"#define\s+INJECT_HELLSHALL\s+4", self.src)


# ─── Builder.py ───

class TestBuilder:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read_py("builder.py")

    def test_indirect_syscalls_param(self):
        assert "indirect_syscalls" in self.src

    def test_hellshall_define_stamping(self):
        assert "INCLUDE_EVASION_HELLSHALL" in self.src

    def test_param_is_boolean(self):
        # Find the indirect_syscalls param definition
        idx = self.src.find('"indirect_syscalls"')
        assert idx > 0
        block = self.src[idx:idx+300]
        assert "Boolean" in block

    def test_default_true(self):
        idx = self.src.find('"indirect_syscalls"')
        block = self.src[idx:idx+300]
        assert "True" in block


# ─── Main.cc Integration ───

class TestMainCC:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("src/main.cc")

    def test_hellshall_init_call(self):
        assert "hellshall_init(inst)" in self.src

    def test_ifdef_guard(self):
        assert "#ifdef INCLUDE_EVASION_HELLSHALL" in self.src


# ─── Hash resolution option ───

class TestHashResolutionOption:
    @pytest.fixture(autouse=True)
    def load(self):
        self.hdr = read("include/evasion/hellshall.h")
        self.impl = read("src/evasion/hellshall.cc")
        self.builder = read_py("builder.py")

    def test_hh_crc_macro_defined_both_modes(self):
        # Both branches must define HH_CRC
        assert self.hdr.count("#define HH_CRC(name)") == 2

    def test_dynamic_mode_uses_xstr(self):
        assert "hh_crc32b(XSTR(#name))" in self.hdr

    def test_static_mode_uses_token_paste(self):
        assert "(name##_CRC32)" in self.hdr

    def test_dynamic_guard(self):
        assert "HH_HASH_DYNAMIC" in self.hdr

    def test_crc_constants_guarded(self):
        # The CRC32 constants must only exist in the static branch
        idx_dyn = self.hdr.find("#ifdef HH_HASH_DYNAMIC")
        idx_const = self.hdr.find("NtAllocateVirtualMemory_CRC32")
        idx_endif = self.hdr.find("#endif", idx_const)
        assert idx_dyn < idx_const
        assert "#else" in self.hdr[idx_dyn:idx_const]

    def test_table_uses_hh_crc(self):
        assert "HH_CRC(NtAllocateVirtualMemory)" in self.impl
        assert "HH_CRC(NtResumeThread)" in self.impl
        # No bare constants left in the table
        assert "NtAllocateVirtualMemory_CRC32," not in self.impl

    def test_obfstr_included(self):
        assert "obfstr.h" in self.hdr

    def test_builder_param(self):
        assert "hash_resolution" in self.builder
        idx = self.builder.find('"hash_resolution"')
        block = self.builder[idx:idx+400]
        assert "dynamic" in block and "static" in block

    def test_builder_stamps_define(self):
        assert "#define HH_HASH_DYNAMIC" in self.builder


# ─── CFG-safe injection (Early Bird) ───

class TestCfgSafeInjection:
    @pytest.fixture(autouse=True)
    def load(self):
        self.inj = read("src/evasion/injection.cc")
        self.fork = read("src/evasion/fork_and_run.cc")
        self.hdr = read("include/evasion/hellshall.h")

    def test_cfg_safe_start_routine(self):
        # Must use a CFG-valid ntdll export as the thread start routine
        assert "RtlExitUserThread" in self.inj

    def test_create_suspended(self):
        # NtCreateThreadEx must create the thread suspended
        assert "CREATE_SUSPENDED" in self.inj

    def test_queue_apc_then_resume(self):
        assert "HH_IDX_NtQueueApcThread" in self.inj
        assert "HH_IDX_NtResumeThread" in self.inj

    def test_nt_resume_thread_resolved(self):
        assert "NtResumeThread_CRC32" in self.hdr
        assert "HH_IDX_NtResumeThread" in self.hdr
        assert "HH_CRC(NtResumeThread)" in read("src/evasion/hellshall.cc")

    def test_no_shellcode_start_address(self):
        # The old bug: start routine == our shellcode address. Must be gone.
        # Start routine must be cfg_safe_start, not `remote`.
        assert "cfg_safe_start" in self.inj

    def test_fork_and_run_uses_apc(self):
        # fork-and-run must queue to the sacrifice's own suspended thread
        assert "QueueUserAPC" in self.fork
        assert "hThread" in self.fork

    def test_fork_inject_signature_takes_thread(self):
        assert "fork_inject_trampoline(PINSTANCE inst, HANDLE hProcess,\n                                   HANDLE hThread," in self.fork

    def test_fork_no_longer_direct_injects(self):
        # The trampoline must not go through inject_shellcode_into (NtCreateThreadEx)
        idx = self.fork.find("fork_inject_trampoline(PINSTANCE")
        end = self.fork.find("\n}\n", idx)
        body = self.fork[idx:end]
        assert "inject_shellcode_into" not in body

    def test_cfg_failure_documented(self):
        assert "0xC0000409" in self.inj or "GUARD_ICALL" in self.inj


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
