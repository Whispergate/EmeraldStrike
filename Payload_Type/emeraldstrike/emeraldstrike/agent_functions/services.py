from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


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
    version = 2
    author = "@Lavender-exe"
    attackmapping = ["T1007"]
    argument_class = ServicesArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        dependencies=["inline_execute"],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return await bof_tasking(taskData, "es_sc_enum.x64.o")

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
