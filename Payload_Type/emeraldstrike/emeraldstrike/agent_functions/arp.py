from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class ArpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ArpCommand(CommandBase):
    cmd = "arp"
    needs_admin = False
    help_cmd = "arp"
    description = "Display the ARP table: IP addresses, MAC addresses, and entry types (static/dynamic) via GetIpNetTable."
    version = 2
    author = "@Lavender-exe"
    attackmapping = ["T1016"]
    argument_class = ArpArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        dependencies=["inline_execute"],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return await bof_tasking(taskData, "es_arp.x64.o")

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
