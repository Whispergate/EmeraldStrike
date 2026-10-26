from mythic_container.MythicCommandBase import *


class SleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="interval",
                type=ParameterType.Number,
                description="Sleep interval in seconds",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="jitter",
                type=ParameterType.Number,
                default_value=0,
                description="Jitter percentage (0-100)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split()
            if len(parts) >= 1:
                self.add_arg("interval", int(parts[0]))
            if len(parts) >= 2:
                self.add_arg("jitter", int(parts[1]))


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep <seconds> [jitter%]"
    description = "Set the agent sleep interval and jitter"
    version = 1
    supported_ui_features = ["callback_table:sleep"]
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = SleepArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        interval = taskData.args.get_arg("interval")
        jitter = taskData.args.get_arg("jitter")
        response.DisplayParams = f"{interval}s {jitter}%"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
