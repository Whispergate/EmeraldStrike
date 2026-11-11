from mythic_container.MythicCommandBase import *


class RouteArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class RouteCommand(CommandBase):
    cmd = "route"
    needs_admin = False
    help_cmd = "route"
    description = "Display the IPv4 routing table via GetIpForwardTable. Returns destination, mask, gateway, metric, and interface index."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1016"]
    argument_class = RouteArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="route", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
