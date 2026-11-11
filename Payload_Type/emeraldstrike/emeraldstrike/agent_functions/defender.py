from mythic_container.MythicCommandBase import *


class DefenderArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class DefenderCommand(CommandBase):
    cmd = "defender"
    needs_admin = False
    help_cmd = "defender"
    description = "Query Windows Defender configuration: real-time monitoring status, antispyware state, and configured exclusion paths, extensions, and processes."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1518.001"]
    argument_class = DefenderArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="defender", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
