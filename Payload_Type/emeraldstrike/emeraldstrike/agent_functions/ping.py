from mythic_container.MythicCommandBase import *


class PingArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="host", type=ParameterType.String, description="Target host", parameter_group_info=[ParameterGroupInfo(required=True)]),
            CommandParameter(name="count", type=ParameterType.String, description="Number of pings", parameter_group_info=[ParameterGroupInfo(required=False)]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("host", self.command_line if self.command_line else "")


class PingCommand(CommandBase):
    cmd = "ping"
    needs_admin = False
    help_cmd = "ping <host> [count]"
    description = "Send ICMP echo requests to a host via IcmpSendEcho. Default 4 pings, 2s timeout. Returns per-ping round-trip time."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1018"]
    argument_class = PingArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="ping", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
