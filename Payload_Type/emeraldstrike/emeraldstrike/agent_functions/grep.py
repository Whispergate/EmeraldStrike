from mythic_container.MythicCommandBase import *


class GrepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="dir", type=ParameterType.String, description="Directory to search", parameter_group_info=[ParameterGroupInfo(required=True)]),
            CommandParameter(name="term", type=ParameterType.String, description="Search term", parameter_group_info=[ParameterGroupInfo(required=True)]),
            CommandParameter(name="ext", type=ParameterType.String, description="Extensions (.txt,.ini)", parameter_group_info=[ParameterGroupInfo(required=False)]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("dir", self.command_line if self.command_line else "")


class GrepCommand(CommandBase):
    cmd = "grep"
    needs_admin = False
    help_cmd = "grep <directory> <term> [.ext,.ext]"
    description = "Search file contents recursively for a text string (case-insensitive). Reads files up to 1MB, max depth 5. Optional extension filter."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1083"]
    argument_class = GrepArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="grep", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
