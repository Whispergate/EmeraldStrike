from mythic_container.MythicCommandBase import *


class ShellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to run via cmd.exe /c",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("command", self.command_line)


class ShellCommand(CommandBase):
    cmd = "shell"
    needs_admin = False
    help_cmd = "shell <command>"
    description = "Execute a command via cmd.exe /c"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1059.003"]
    argument_class = ShellArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("command")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
