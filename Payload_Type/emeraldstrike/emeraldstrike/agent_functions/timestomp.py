from mythic_container.MythicCommandBase import *


class TimestompArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="source", type=ParameterType.String, description="Source file", parameter_group_info=[ParameterGroupInfo(required=True)]),
            CommandParameter(name="dest", type=ParameterType.String, description="Destination file", parameter_group_info=[ParameterGroupInfo(required=True)]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("source", self.command_line if self.command_line else "")


class TimestompCommand(CommandBase):
    cmd = "timestomp"
    needs_admin = False
    help_cmd = "timestomp <source_file> <dest_file>"
    description = "Copy file timestamps (created, modified, accessed) from a source file to a destination file."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1070.006"]
    argument_class = TimestompArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="timestomp", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
