from mythic_container.MythicCommandBase import *


class RunuArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                description="Domain (use . for local)",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=3)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to execute",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Usage: runu -domain CORP -username admin -password pass -command whoami")


class RunuCommand(CommandBase):
    cmd = "runu"
    needs_admin = False
    help_cmd = "runu -domain CORP -username admin -password pass -command whoami"
    description = "Run a command as a different user using CreateProcessWithLogonW."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.002"]
    argument_class = RunuArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        domain = taskData.args.get_arg("domain")
        username = taskData.args.get_arg("username")
        command = taskData.args.get_arg("command")
        response.DisplayParams = f"{domain}\\{username}: {command}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
