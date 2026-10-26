from mythic_container.MythicCommandBase import *


class ConfigArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["get", "set"],
                default_value="get",
                description="Get or set config values",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="key",
                type=ParameterType.String,
                default_value="",
                description="Config key to set (sleep, jitter, killdate)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="value",
                type=ParameterType.Number,
                default_value=0,
                description="New value for the config key",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split()
            if len(parts) == 0 or parts[0] == "get":
                self.add_arg("action", "get")
            elif parts[0] == "set" and len(parts) >= 3:
                self.add_arg("action", "set")
                self.add_arg("key", parts[1])
                self.add_arg("value", int(parts[2]))


class ConfigCommand(CommandBase):
    cmd = "config"
    needs_admin = False
    help_cmd = "config [get | set <key> <value>]"
    description = "View or modify agent configuration"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = ConfigArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
