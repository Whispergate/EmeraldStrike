from mythic_container.MythicCommandBase import *


class WindowlistArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class WindowlistCommand(CommandBase):
    cmd = "windowlist"
    needs_admin = False
    help_cmd = "windowlist"
    description = "List visible windows with their titles and owning PIDs via EnumWindows."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1010"]
    argument_class = WindowlistArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="windowlist", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
