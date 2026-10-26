from mythic_container.MythicCommandBase import *


class ExitArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="method",
                type=ParameterType.ChooseOne,
                choices=["thread", "process"],
                default_value="thread",
                description="Exit method: thread (ExitThread, keeps host process alive) or process (ExitProcess, kills host process)",
            ),
        ]

    async def parse_arguments(self):
        if self.command_line and not self.command_line.startswith("{"):
            self.add_arg("method", self.command_line.strip())
        else:
            self.load_args_from_json_string(self.command_line)


class ExitCommand(CommandBase):
    cmd = "exit"
    needs_admin = False
    help_cmd = "exit [thread|process]"
    description = "Exit the agent. 'thread' (default) calls ExitThread, keeping the host process alive. 'process' calls ExitProcess, terminating the host process."
    version = 2
    supported_ui_features = ["callback_table:exit"]
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = ExitArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        method = taskData.args.get_arg("method") or "thread"
        taskData.args.add_arg("method_int", "1" if method == "process" else "0", type=ParameterType.String)
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
            DisplayParams=f" -Method {method}",
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
