from mythic_container.MythicCommandBase import *


class SoftwareArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class SoftwareCommand(CommandBase):
    cmd = "software"
    needs_admin = False
    help_cmd = "software"
    description = "List installed software from the HKLM and HKCU Uninstall registry keys. Returns name, version, publisher, and install location."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1518"]
    argument_class = SoftwareArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="software", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
