from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import base64
import json
import struct


class BOFArgError(Exception):
    """Raised when operator-supplied arguments don't match the pack format."""


_TYPE_NAMES = {"z": "string", "Z": "wstring", "i": "int32", "s": "int16", "b": "binary"}

# COFF Machine field (first 2 bytes, little-endian) of valid BOF object files.
# Guards against tasking a non-COFF file (e.g. a same-named .json schema) as
# a BOF - executing garbage in-process kills the implant.
_COFF_MACHINES = {b"\x64\x86": "x64", b"\x4c\x01": "i386"}


def _split_bof_args(s: str) -> list:
    """Split arguments on whitespace, respecting double quotes. Preserves backslashes.

    A quoted empty string ("") is preserved as an empty argument rather than
    dropped - BOFs like RawHive take optional strings packed as "".
    """
    args = []
    current = []
    in_quote = False
    quoted_empty = False
    for ch in s:
        if ch == '"':
            in_quote = not in_quote
            quoted_empty = True
        elif ch in (' ', '\t') and not in_quote:
            if current or quoted_empty:
                args.append(''.join(current))
                current = []
                quoted_empty = False
        else:
            current.append(ch)
    if current or quoted_empty:
        args.append(''.join(current))
    return args


def _bof_pack(fmt: str, args: list) -> bytes:
    """Pack arguments into CS-compatible binary format for BOF consumption.

    Format chars: z=ANSI string, Z=wide string, i=int32, s=int16, b=binary(base64).
    Strict: every format char consumes exactly one argument. Count or type
    mismatches raise BOFArgError with the offending position instead of
    silently packing empty strings (which produced int('') tracebacks).
    """
    if len(args) != len(fmt):
        expected = ', '.join(_TYPE_NAMES.get(c, c) for c in fmt)
        raise BOFArgError(
            f"ArgumentTypes '{fmt}' expects {len(fmt)} argument(s) ({expected}), "
            f"got {len(args)}: {args}"
        )
    buf = b""
    for idx, (c, val) in enumerate(zip(fmt, args), start=1):
        if c == "z":
            encoded = val.encode("utf-8") + b"\x00"
            buf += struct.pack("<I", len(encoded)) + encoded
        elif c == "Z":
            encoded = val.encode("utf-16-le") + b"\x00\x00"
            buf += struct.pack("<I", len(encoded)) + encoded
        elif c == "i":
            try:
                buf += struct.pack("<I", int(val, 10) & 0xFFFFFFFF)
            except ValueError:
                raise BOFArgError(f"argument {idx} ('{val}') is not a valid int32 for ArgumentTypes 'i'")
        elif c == "s":
            try:
                buf += struct.pack("<H", int(val, 10) & 0xFFFF)
            except ValueError:
                raise BOFArgError(f"argument {idx} ('{val}') is not a valid int16 for ArgumentTypes 's'")
        elif c == "b":
            try:
                raw = base64.b64decode(val, validate=True)
            except Exception:
                raise BOFArgError(f"argument {idx} is not valid base64 for ArgumentTypes 'b'")
            buf += struct.pack("<I", len(raw)) + raw
        else:
            raise BOFArgError(
                f"unknown ArgumentTypes char '{c}' at position {idx} (valid: z Z i s b)"
            )
    return buf


class InlineExecuteArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="bof_name",
                cli_name="BOF",
                display_name="BOF",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_bof_files,
                description="Previously registered BOF to execute",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="bof_file",
                display_name="New BOF",
                type=ParameterType.File,
                description="Upload a new BOF (.o COFF object file). After uploading, reuse via the Default tab.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="bof_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                default_value="",
                description="Arguments to pass to the BOF, one per ArgumentTypes char, in bof_pack order (space-separated, double quotes for strings with spaces or empty strings)",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=2),
                ],
            ),
            CommandParameter(
                name="argument_types",
                cli_name="ArgumentTypes",
                display_name="Argument Types",
                type=ParameterType.String,
                default_value="",
                description="CS bof_pack format string: z=ANSI string, Z=wide string, i=int32, s=int16, b=binary(b64). Auto-filled when the BOF was registered with an aggressor script. Default: one 'z' per argument.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=3),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=3),
                ],
            ),
            CommandParameter(
                name="fork_and_run",
                cli_name="ForkAndRun",
                display_name="Fork & Run",
                type=ParameterType.Boolean,
                description="Run BOF in a sacrificial process (fork-and-run) instead of inline. Uses the configured spawnto process. Note: BOFs that interact with agent state (tokens, config) may not work in fork-and-run mode.",
                default_value=False,
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=4),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=4),
                ],
            ),
        ]

    async def get_bof_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        response = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        if file_resp.Success:
            names = []
            for f in file_resp.Files:
                if f.Filename not in names and f.Filename.endswith(".o"):
                    names.append(f.Filename)
            response.Success = True
            response.Choices = names
        else:
            response.Error = file_resp.Error
        return response

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(InlineExecuteCommand.help_cmd))


class InlineExecuteCommand(CommandBase):
    cmd = "inline_execute"
    needs_admin = False
    help_cmd = "inline_execute -BOF <bof.o> [-Arguments 'args'] [-ArgumentTypes '<zZisb fmt>']"
    description = "Execute a Beacon Object File (BOF) inline"
    version = 4
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1059"]
    argument_class = InlineExecuteArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    @staticmethod
    def _validate_coff(name: str, data: bytes):
        """Reject non-COFF content before it reaches the agent.

        The Mythic FileSearch Filename filter substring-matches the bytea name
        column, so 'rawhive.x64.o' also matches 'rawhive.x64.o.json'. Before
        this check, a schema JSON was once served as BOF bytes and executing
        it in-process killed the implant.
        """
        machine = data[:2]
        if machine not in _COFF_MACHINES:
            raise BOFArgError(
                f"'{name}' ({len(data)} bytes) does not look like a COFF object "
                f"(machine magic {machine.hex()}); refusing to task it as a BOF"
            )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

        # One broad search resolves BOTH the BOF (exact-name match) and its
        # optional '<bof>.json' schema. The Filename RPC filter cannot be
        # trusted for exact matching (substring behavior, bytea column).
        broad = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=taskData.Callback.ID,
            LimitByCallback=False,
            Filename="",
        ))

        if taskData.args.get_parameter_group_name() == "New":
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileID=taskData.args.get_arg("bof_file"),
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = "Failed to find uploaded BOF file"
                return response

            file_id = taskData.args.get_arg("bof_file")
            bof_name = file_search.Files[0].Filename
            taskData.args.add_arg("bof_name", bof_name)
            taskData.args.remove_arg("bof_file")
        else:
            bof_name = taskData.args.get_arg("bof_name")
            if not broad.Success:
                response.Success = False
                response.Error = f"Failed to search Mythic files: {broad.Error}"
                return response
            exact = [f for f in broad.Files if f.Filename == bof_name]
            if not exact:
                response.Success = False
                response.Error = f"Failed to find BOF '{bof_name}' in Mythic"
                return response
            file_id = exact[0].AgentFileId

        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get BOF content: {file_content.Error}"
            return response

        try:
            self._validate_coff(bof_name, file_content.Content)
        except BOFArgError as e:
            response.Success = False
            response.Error = str(e)
            return response

        # Schema lookup: exact-name '<bof>.json' from the same broad search.
        schema = None
        if broad.Success:
            schema_file = next((f for f in broad.Files if f.Filename == bof_name + ".json"), None)
            if schema_file:
                content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                    AgentFileId=schema_file.AgentFileId,
                ))
                if content.Success:
                    try:
                        schema = json.loads(content.Content)
                    except (ValueError, UnicodeDecodeError):
                        schema = None

        taskData.args.add_arg("bof_data", base64.b64encode(file_content.Content).decode(), ParameterType.String,
                              parameter_group_info=[
                                  ParameterGroupInfo(group_name="Default"),
                                  ParameterGroupInfo(group_name="New"),
                              ])

        bof_len = len(file_content.Content)
        arguments = taskData.args.get_arg("bof_arguments") or ""
        arg_types = taskData.args.get_arg("argument_types") or ""

        auto_fmt = False
        if schema and not arg_types and schema.get("format"):
            # Format string extracted from the BOF's aggressor script at
            # register time. Fat .cnas (arg inference) still pack in this
            # order - only the CS-side UX is not reproduced.
            arg_types = schema["format"]
            auto_fmt = True

        packed_args = b""
        if arguments:
            split_args = _split_bof_args(arguments)
            if not arg_types:
                arg_types = "z" * len(split_args)
            try:
                packed_args = _bof_pack(arg_types, split_args)
            except BOFArgError as e:
                response.Success = False
                msg = str(e)
                if schema and schema.get("help_long"):
                    msg += f"\n{schema.get('alias', bof_name)} usage (from its aggressor script):\n{schema['help_long']}"
                elif schema and schema.get("help_short"):
                    msg += f"\n{schema.get('alias', bof_name)}: {schema['help_short']}"
                if schema and schema.get("thin") is False:
                    msg += "\nNote: this BOF has a fat .cna (positional arg inference); pass one argument per format char in bof_pack order."
                response.Error = msg
                return response

        taskData.args.add_arg("bof_args", base64.b64encode(packed_args).decode(), ParameterType.String,
                              parameter_group_info=[
                                  ParameterGroupInfo(group_name="Default"),
                                  ParameterGroupInfo(group_name="New"),
                              ])

        fork = taskData.args.get_arg("fork_and_run") or False
        taskData.args.add_arg("fork_and_run_int", 1 if fork else 0, ParameterType.Number,
                              parameter_group_info=[
                                  ParameterGroupInfo(group_name="Default"),
                                  ParameterGroupInfo(group_name="New"),
                              ])

        schema_note = ""
        if schema:
            schema_note = f" [{schema.get('alias', '?')}: fmt={schema.get('format', '?')}"
            if auto_fmt:
                schema_note += " (auto)"
            if schema.get("thin") is False:
                schema_note += ", fat cna: args in bof_pack order"
            schema_note += "]"

        mode_tag = " [fork-and-run]" if fork else " [inline]"

        if arguments:
            response.DisplayParams = f"-BOF {bof_name} ({bof_len} bytes) -Arguments '{arguments}'{schema_note}{mode_tag}"
        else:
            response.DisplayParams = f"-BOF {bof_name} ({bof_len} bytes){schema_note}{mode_tag}"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
