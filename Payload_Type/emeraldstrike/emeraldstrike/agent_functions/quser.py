from mythic_container.MythicCommandBase import *


class QuserArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class QuserCommand(CommandBase):
    cmd = "quser"
    needs_admin = False
    help_cmd = "quser"
    description = "List logged-on user sessions via WTSEnumerateSessionsW. Returns session ID, name, state (active/disconnected/idle), and username."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1033"]
    argument_class = QuserArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="quser", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
