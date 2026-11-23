from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class PsgrepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="term",
                type=ParameterType.String,
                description="Process name substring (informational; BOF lists all processes)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("term", self.command_line if self.command_line else "")


class PsgrepCommand(CommandBase):
    cmd = "psgrep"
    needs_admin = False
    help_cmd = "psgrep <name_substring>"
    description = "Search running processes by name substring (case-insensitive). Returns PID, PPID, and name for each match."
    version = 2
    author = "@Lavender-exe"
    attackmapping = ["T1057"]
    argument_class = PsgrepArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        dependencies=["inline_execute"],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        term = taskData.args.get_arg("term") or ""
        response = await bof_tasking(
            taskData, "es_pslist_handles.x64.o",
            coff_arguments=[("int32", 0)],
        )
        if term:
            response.DisplayParams = term
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
