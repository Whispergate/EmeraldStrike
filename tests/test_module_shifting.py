"""
T1 Unit Tests - Module Shifting (naksyn ModuleShifting extension)
Validates backup/restore structure, shift-and-restore bootstrap path,
builder wiring, and config guards.
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

# ─── Module Stomp Header (shift extensions) ───

class TestModuleStompHeaderShift:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("include/evasion/module_stomp.h")

    def test_shift_fields_gated(self):
        # Shift-only fields must be inside the INCLUDE_EVASION_MODULE_SHIFT gate
        assert "#ifdef INCLUDE_EVASION_MODULE_SHIFT" in self.src
        idx = self.src.index("#ifdef INCLUDE_EVASION_MODULE_SHIFT")
        block = self.src[idx:idx + 800]
        for field in ["bShiftActive", "dwShiftPad", "pTextBackup", "szTextBackup",
                      "dwTextProt", "pPdataBackup", "bBackupRestored"]:
            assert field in block, f"Missing shift field: {field}"

    def test_shared_loader_declared(self):
        assert "BOOL ms_load_sacrifice(PINSTANCE inst, PMODULE_STOMP_CTX ctx);" in self.src

    def test_restore_declared(self):
        assert "VOID module_shift_restore(PINSTANCE inst);" in self.src

    def test_pad_normalization(self):
        # Builder stamps MODULE_SHIFT_PAD 1; header translates to 0x200
        assert "#if MODULE_SHIFT_PAD == 1" in self.src
        assert "#define MODULE_SHIFT_PAD 0x200" in self.src
        assert "#define MODULE_SHIFT_PAD 0" in self.src


# ─── Module Stomp Implementation (backup/restore) ───

class TestModuleStompShiftImpl:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("src/evasion/module_stomp.cc")

    def test_shared_loader_exists(self):
        assert "BOOL ms_load_sacrifice(PINSTANCE inst, PMODULE_STOMP_CTX ctx)" in self.src
        assert "BOOL module_stomp_init(PINSTANCE inst)" in self.src
        # stomp init delegates to the shared loader
        assert "ms_load_sacrifice(inst, ctx)" in self.src

    def test_veh_uses_static_ctx(self):
        # The VEH handler must work for both the persistent stomp and the
        # shift path's stack-local context
        assert "g_ms_ctx" in self.src
        assert "PMODULE_STOMP_CTX ctx = g_ms_ctx;" in self.src

    def test_shift_backup_of_text(self):
        assert "ctx->pTextBackup = es_malloc(inst" in self.src
        assert "ctx->szTextBackup = ctx->szStomp" in self.src
        assert "ctx->dwTextProt = oldProt" in self.src
        assert "es_memcpy(ctx->pTextBackup, ctx->SacText.pBase" in self.src

    def test_shift_backup_of_pdata(self):
        assert "ctx->pPdataBackup" in self.src
        assert "ctx->dwPdataProt = pdataOldProt" in self.src

    def test_pad_offset_copy(self):
        # Agent blob lands at section_base + pad, not at the section base
        assert "copyDest += pad;" in self.src
        assert "PBYTE newBase = (PBYTE)copyDest;" in self.src
        assert "ctx->szStomp = (SIZE_T)pad + inst->Base.Length;" in self.src

    def test_restore_stub_machine_code(self):
        # Position-independent restore stub: rep movsb + VirtualProtect + exit
        assert "ms_restore_stub" in self.src
        assert "0xF3, 0xA4" in self.src          # rep movsb
        assert "0x48, 0x83, 0xE4, 0xF0" in self.src  # and rsp, -16
        assert "call r8" in self.src
        assert "jmp r15" in self.src

    def test_restore_function(self):
        assert "VOID module_shift_restore(PINSTANCE inst)" in self.src
        # one-shot guard
        assert "ctx->bBackupRestored = TRUE;" in self.src
        assert "if (!ctx->bShiftActive || ctx->bBackupRestored) return;" in self.src
        # stub staged outside the restored region, then jumped into
        assert "VirtualAlloc" in self.src
        assert '"call %7' in self.src

    def test_restore_runs_before_both_exit_paths(self):
        main = read("src/main.cc")
        # restore must precede ExitProcess and gate_ExitThread in agent_main
        assert "module_shift_restore(inst);" in main
        assert main.index("module_shift_restore(inst);") < main.index("inst->Win32.ExitProcess(0);")

    def test_shift_gates(self):
        assert "#ifdef INCLUDE_EVASION_MODULE_SHIFT" in self.src
        assert "#ifdef _WIN64" in self.src


# ─── Module Shift (shift-and-restore bootstrap execution) ───

class TestModuleShift:
    @pytest.fixture(autouse=True)
    def load(self):
        self.header = read("include/evasion/module_shift.h")
        self.src = read("src/evasion/module_shift.cc")

    def test_include_guard(self):
        assert "EMERALDSTRIKE_MODULE_SHIFT_H" in self.header
        assert "#ifdef INCLUDE_EVASION_MODULE_SHIFT" in self.header
        assert "#ifdef _WIN64" in self.header

    def test_impl_gated_on_fork_and_run_commands(self):
        # Only contributes code when execute_assembly or inline_execute built
        assert "defined(INCLUDE_CMD_EXECUTE_ASSEMBLY) || defined(INCLUDE_CMD_INLINE_EXECUTE)" in self.src
        assert "#ifdef INCLUDE_EVASION_MODULE_SHIFT" in self.src
        assert "#ifdef _WIN64" in self.src

    def test_shift_exec_write_execute_restore(self):
        assert "DWORD module_shift_exec(PINSTANCE inst, BYTE* shellcode, DWORD len, PVOID param)" in self.src
        # backup before overwrite
        assert "es_memcpy(backup, dst, len);" in self.src
        assert "es_memcpy(dst, shellcode, len);" in self.src
        # restore after execution
        assert "es_memcpy(dst, backup, len);" in self.src
        assert "es_free(inst, backup);" in self.src

    def test_reuses_shared_sacrifice_loader(self):
        # The shift path must NOT re-enter the VEH/single-step loader (the
        # handler's register-scavenging heuristic dereferences garbage on a
        # second entry and kills the process). It uses the plain
        # LoadLibraryExW DONT_RESOLVE mapping instead.
        # no CALL to the VEH loader (comment mentions are fine)
        assert "ms_load_sacrifice(inst" not in self.src
        assert "ms_load_sacrifice(&sctx" not in self.src
        assert "ms_map_sacrifice_ex(inst, &sctx" in self.src
        # stack-local context so a persistent stomp is untouched
        assert "MODULE_STOMP_CTX sctx;" in self.src

    def test_pad_offset_in_shift_exec(self):
        assert "MODULE_SHIFT_PAD" in self.src
        assert "(PBYTE)sctx.SacText.pBase + MODULE_SHIFT_PAD" in self.src
        assert "sctx.SacText.dwVirtualSize < (DWORD)MODULE_SHIFT_PAD + len" in self.src

    def test_protection_flip_to_original(self):
        # restore original section protection (RX), not a hardcoded value
        assert "origProt" in self.src
        assert "inst->Win32.VirtualProtect(sctx.SacText.pBase, sctx.SacText.dwVirtualSize,\n                                origProt" in self.src

    def test_assembly_and_bof_runners(self):
        assert "BOOL module_shift_run_assembly" in self.src
        assert "BOOL module_shift_run_bof" in self.src
        # gated on stamped bootstrap blobs
        assert "#ifdef CLR_BOOTSTRAP_SIZE" in self.src
        assert "#ifdef BOF_BOOTSTRAP_SIZE" in self.src
        assert "CLR_BOOTSTRAP_BYTES" in self.src
        assert "BOF_BOOTSTRAP_BYTES" in self.src
        # same data-region layout as the fork path
        assert "(UINT64)(ULONG_PTR)hW" in self.src

    def test_output_drain_reuses_fork_collect(self):
        assert "fork_collect_output(inst, &fctx" in self.src


# ─── Fork-and-run wiring ───

class TestForkAndRunWiring:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("src/evasion/fork_and_run.cc")

    def test_assembly_shift_first_with_fallback(self):
        assert "#if defined(INCLUDE_EVASION_MODULE_SHIFT) && defined(MODULE_SHIFT_BOOTSTRAP)" in self.src
        assert "module_shift_run_assembly(inst, asm_data, asm_len" in self.src
        assert "return TRUE;" in self.src

    def test_bof_shift_first_with_fallback(self):
        assert "module_shift_run_bof(inst, bof_data, bof_len" in self.src

    def test_fork_path_still_present(self):
        # the remote fork path remains as fallback
        assert "fork_spawn(inst, &ctx)" in self.src
        assert "fork_run_assembly" in self.src or "fork_inject_trampoline" in self.src


# ─── Builder wiring ───

class TestBuilderWiring:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read_py("builder.py")

    def test_module_shift_param(self):
        assert 'name="module_shift"' in self.src
        assert 'name="module_shift_pad"' in self.src
        assert 'name="shift_bootstrap"' in self.src

    def test_defaults(self):
        m = re.search(r'name="module_shift",.*?default_value=(\w+)', self.src, re.S)
        assert m and m.group(1) == "False"
        m = re.search(r'name="module_shift_pad",.*?default_value=(\w+)', self.src, re.S)
        assert m and m.group(1) == "True"
        m = re.search(r'name="shift_bootstrap",.*?default_value=(\w+)', self.src, re.S)
        assert m and m.group(1) == "False"

    def test_hide_conditions_x64_and_udrl(self):
        for param in ["module_shift", "shift_bootstrap"]:
            i = self.src.index('name="%s"' % param)
            block = self.src[i:i + 1400]
            assert 'HideCondition(name="architecture", operand=HideConditionOperand.NotEQ, value="x64")' in block
            assert 'HideCondition(name="loader_type", operand=HideConditionOperand.EQ, value="udrl-vs")' in block

    def test_pad_hidden_when_shift_off(self):
        i = self.src.index('name="module_shift_pad"')
        block = self.src[i:i + 900]
        # Mythic HideCondition values must be strings - a bool value breaks
        # payload-definition validation server-side ("bad type for
        # *_PARAMETER_TYPE_STRING: bool").
        assert 'HideCondition(name="module_shift", operand=HideConditionOperand.NotEQ, value="True")' in block
        # no bare-bool value anywhere in the hide_conditions list
        hc = block[block.index("hide_conditions"):]
        hc = hc[:hc.index("],") + 2] if "]," in hc else hc
        assert "value=True," not in hc and "value=False," not in hc
        assert not hc.rstrip().endswith("value=True")

    def test_shift_implies_stomp_define(self):
        # Module shifting REMOVED (2026-11-08): the builder must never emit
        # shift defines - the shift path's second loader entry re-enters with
        # live DRs and crashes with an unhandled #DB. Parameters are still
        # accepted (payload-definition compatibility) but silently ignored.
        assert 'defines.append("#define INCLUDE_EVASION_MODULE_SHIFT")' not in self.src
        assert 'defines.append("#define MODULE_SHIFT_PAD 1")' not in self.src
        assert 'defines.append("#define MODULE_SHIFT_BOOTSTRAP 1")' not in self.src
        assert "REMOVED (2026-11-08)" in self.src

    def test_shift_disabled_under_udrl(self):
        # force-disabled for udrl-vs like module_stomp
        assert self.src.count('if loader_type == "udrl-vs":') >= 3


# ─── Config guards ───

class TestConfigGuards:
    @pytest.fixture(autouse=True)
    def load(self):
        self.src = read("include/config.h")

    def test_no_hardcoded_shift_defines(self):
        # shift is a build parameter - must never be baked into the template
        assert "INCLUDE_EVASION_MODULE_SHIFT" not in self.src
        assert "MODULE_SHIFT_PAD" not in self.src
        assert "MODULE_SHIFT_BOOTSTRAP" not in self.src

    def test_placeholders_intact(self):
        for ph in ["%TRANSPORT_DEFINE%", "%CONFIG_BYTES%", "%COMMAND_DEFINES%",
                   "%EVASION_DEFINES%", "%SLEEPMASK_COFF_DEFINE%",
                   "%CLR_BOOTSTRAP_DEFINE%", "%BOF_BOOTSTRAP_DEFINE%"]:
            assert ph in self.src, f"Missing placeholder: {ph}"

    def test_existing_constants_untouched(self):
        assert "INJECT_HELLSHALL" in self.src
        assert "SPOOF_NONE" in self.src
        assert "CALLSTACK_SPOOF_MODE" in self.src

    def test_makefile_picks_up_module_shift(self):
        mk = read("Makefile")
        assert "src/evasion/*.cc" in mk
