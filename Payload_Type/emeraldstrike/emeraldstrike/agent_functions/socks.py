from mythic_container.MythicCommandBase import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                description="Start or stop the SOCKS proxy",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                description="Local port to listen on (for start)",
                default_value=1080,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            if len(parts) >= 1:
                self.add_arg("action", parts[0])
            if len(parts) >= 2:
                self.add_arg("port", int(parts[1]))


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks start [port]  |  socks stop"
    description = "Start or stop a SOCKS4a proxy. Traffic is tunneled through the beacon."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1090"]
    argument_class = SocksArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        port = taskData.args.get_arg("port")
        if action == "start":
            response.DisplayParams = f"start :{port}"
        else:
            response.DisplayParams = "stop"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
