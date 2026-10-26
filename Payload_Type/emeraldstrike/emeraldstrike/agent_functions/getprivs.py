from mythic_container.MythicCommandBase import *


class GetPrivsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class GetPrivsCommand(CommandBase):
    cmd = "getprivs"
    needs_admin = False
    help_cmd = "getprivs"
    description = "Enable all available privileges in the current access token."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.002"]
    argument_class = GetPrivsArguments
    browser_script = BrowserScript(script_name="getprivs", author="@Lavender-exe", for_new_ui=True)
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
