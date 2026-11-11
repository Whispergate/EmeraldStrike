from mythic_container.MythicCommandBase import *


class WgetArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="url", type=ParameterType.String, description="URL to download", parameter_group_info=[ParameterGroupInfo(required=True)]),
            CommandParameter(name="path", type=ParameterType.String, description="Output path", parameter_group_info=[ParameterGroupInfo(required=True)]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("url", self.command_line if self.command_line else "")


class WgetCommand(CommandBase):
    cmd = "wget"
    needs_admin = False
    help_cmd = "wget <url> <output_path>"
    description = "Download a file from a URL to a local path via WinInet. Returns bytes written to disk."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1105"]
    argument_class = WgetArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="wget", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
