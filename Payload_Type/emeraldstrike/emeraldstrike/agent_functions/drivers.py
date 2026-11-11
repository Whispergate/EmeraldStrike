from mythic_container.MythicCommandBase import *


class DriversArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class DriversCommand(CommandBase):
    cmd = "drivers"
    needs_admin = False
    help_cmd = "drivers"
    description = "List loaded kernel drivers with base addresses via EnumDeviceDrivers. Useful for identifying EDR/AV kernel components."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1082"]
    argument_class = DriversArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="drivers", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
