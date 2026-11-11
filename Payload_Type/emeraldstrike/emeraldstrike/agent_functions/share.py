from mythic_container.MythicCommandBase import *


class ShareArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ShareCommand(CommandBase):
    cmd = "share"
    needs_admin = False
    help_cmd = "share"
    description = "Enumerate SMB shares on the local machine via NetShareEnum. Returns share name, local path, and type."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1135"]
    argument_class = ShareArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="share", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
