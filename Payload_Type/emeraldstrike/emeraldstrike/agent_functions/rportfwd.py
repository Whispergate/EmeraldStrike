from mythic_container.MythicCommandBase import *


class RportfwdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                description="Start or stop a reverse port forward",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="bind_port",
                type=ParameterType.Number,
                description="Port to listen on (on the target)",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="forward_host",
                type=ParameterType.String,
                description="Host to forward traffic to (from operator perspective)",
                default_value="127.0.0.1",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="forward_port",
                type=ParameterType.Number,
                description="Port to forward traffic to",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            if len(parts) >= 2:
                self.add_arg("action", parts[0])
                self.add_arg("bind_port", int(parts[1]))
            if len(parts) >= 3:
                self.add_arg("forward_host", parts[2])
            if len(parts) >= 4:
                self.add_arg("forward_port", int(parts[3]))


class RportfwdCommand(CommandBase):
    cmd = "rportfwd"
    needs_admin = False
    help_cmd = "rportfwd start <bind_port> <fwd_host> <fwd_port>  |  rportfwd stop <bind_port>"
    description = "Start or stop a reverse port forward. Listens on the target and forwards traffic back through the C2 channel."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1090.001"]
    argument_class = RportfwdArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        bind_port = taskData.args.get_arg("bind_port")
        if action == "start":
            fwd_host = taskData.args.get_arg("forward_host") or "127.0.0.1"
            fwd_port = taskData.args.get_arg("forward_port") or bind_port
            response.DisplayParams = f"start :{bind_port} -> {fwd_host}:{fwd_port}"
        else:
            response.DisplayParams = f"stop :{bind_port}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
