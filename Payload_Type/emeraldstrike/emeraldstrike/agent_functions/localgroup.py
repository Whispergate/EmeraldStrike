from mythic_container.MythicCommandBase import *


class LocalgroupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class LocalgroupCommand(CommandBase):
    cmd = "localgroup"
    needs_admin = False
    help_cmd = "localgroup"
    description = "Enumerate local groups on the machine via NetLocalGroupEnum. Returns group names and descriptions."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1069.001"]
    argument_class = LocalgroupArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="localgroup", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
