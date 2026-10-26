from mythic_container.MythicCommandBase import *


class Rev2selfArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class Rev2selfCommand(CommandBase):
    cmd = "rev2self"
    needs_admin = False
    help_cmd = "rev2self"
    description = "Revert to the agent's original access token, dropping any stolen or impersonated token."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134"]
    argument_class = Rev2selfArguments
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
