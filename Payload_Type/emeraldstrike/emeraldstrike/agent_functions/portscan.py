from mythic_container.MythicCommandBase import *


class PortscanArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="host", type=ParameterType.String, description="Target host", parameter_group_info=[ParameterGroupInfo(required=True)]),
            CommandParameter(name="ports", type=ParameterType.String, description="Ports (80,443,1000-1100)", parameter_group_info=[ParameterGroupInfo(required=True)]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("host", self.command_line if self.command_line else "")


class PortscanCommand(CommandBase):
    cmd = "portscan"
    needs_admin = False
    help_cmd = "portscan <host> <port,port-port,...>"
    description = "TCP connect scan against a host. Supports comma-separated ports and ranges (e.g. 80,443,8000-8100). Non-blocking sockets with 1-second timeout."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1046"]
    argument_class = PortscanArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="portscan", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
