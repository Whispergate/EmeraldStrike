from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


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
    version = 2
    author = "@Lavender-exe"
    attackmapping = ["T1069.001"]
    argument_class = LocalgroupArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        dependencies=["inline_execute"],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return await bof_tasking(taskData, "es_netlocalgroup.x64.o")

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
