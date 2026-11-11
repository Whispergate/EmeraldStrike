from mythic_container.MythicCommandBase import *


class CurlArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="url", type=ParameterType.String, description="URL", parameter_group_info=[ParameterGroupInfo(required=True)]),
            CommandParameter(name="method", type=ParameterType.String, description="HTTP method", parameter_group_info=[ParameterGroupInfo(required=False)]),
            CommandParameter(name="body", type=ParameterType.String, description="Request body", parameter_group_info=[ParameterGroupInfo(required=False)]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("url", self.command_line if self.command_line else "")


class CurlCommand(CommandBase):
    cmd = "curl"
    needs_admin = False
    help_cmd = "curl <url> [method] [body]"
    description = "Make an HTTP/HTTPS request via WinInet. Supports custom method and request body. Returns status code and response body (up to 64KB)."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1071.001"]
    argument_class = CurlArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="curl", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
