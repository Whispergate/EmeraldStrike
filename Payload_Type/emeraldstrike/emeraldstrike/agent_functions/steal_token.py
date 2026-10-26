from mythic_container.MythicCommandBase import *


class StealTokenArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="Process ID to steal token from",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("pid", int(self.command_line.strip()))


class StealTokenCommand(CommandBase):
    cmd = "steal_token"
    needs_admin = False
    help_cmd = "steal_token <pid>"
    description = "Steal an access token from a target process and impersonate it for future tasks."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.001"]
    argument_class = StealTokenArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = f"PID {taskData.args.get_arg('pid')}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
