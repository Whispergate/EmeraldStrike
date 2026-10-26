from mythic_container.MythicCommandBase import *


class JobsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class JobsCommand(CommandBase):
    cmd = "jobs"
    needs_admin = False
    help_cmd = "jobs"
    description = "List running background jobs (long-running tasks, SOCKS proxies, port forwards)."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = JobsArguments
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
