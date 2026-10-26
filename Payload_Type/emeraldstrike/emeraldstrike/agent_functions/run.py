from mythic_container.MythicCommandBase import *


class RunArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="executable",
                type=ParameterType.String,
                description="Path to executable",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Arguments to pass",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split(None, 1)
            self.add_arg("executable", parts[0])
            self.add_arg("arguments", parts[1] if len(parts) > 1 else "")


class RunCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run <executable> [arguments]"
    description = "Execute a program directly (no cmd.exe) and capture its output."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1106"]
    argument_class = RunArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        exe = taskData.args.get_arg("executable")
        args = taskData.args.get_arg("arguments")
        response.DisplayParams = f"{exe}" + (f" {args}" if args else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
