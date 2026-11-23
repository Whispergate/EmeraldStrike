from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


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
    version = 2
    author = "@Lavender-exe"
    attackmapping = ["T1016"]
    argument_class = RouteArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        dependencies=["inline_execute"],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return await bof_tasking(taskData, "es_routeprint.x64.o")

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
