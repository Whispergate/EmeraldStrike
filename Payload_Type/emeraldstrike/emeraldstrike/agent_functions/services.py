from mythic_container.MythicCommandBase import *


class ServicesArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ServicesCommand(CommandBase):
    cmd = "services"
    needs_admin = False
    help_cmd = "services"
    description = "Enumerate Windows services via the Service Control Manager. Returns service name, display name, state (running/stopped), and PID."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1007"]
    argument_class = ServicesArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="services", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
