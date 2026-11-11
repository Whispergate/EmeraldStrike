from mythic_container.MythicCommandBase import *


class ProcinfoArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="pid", type=ParameterType.String, description="Process ID", parameter_group_info=[ParameterGroupInfo(required=True)]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("pid", self.command_line if self.command_line else "")


class ProcinfoCommand(CommandBase):
    cmd = "procinfo"
    needs_admin = False
    help_cmd = "procinfo <pid>"
    description = "Get detailed info for a process by PID: full image path and owning user from the process token."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1057"]
    argument_class = ProcinfoArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="procinfo", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
