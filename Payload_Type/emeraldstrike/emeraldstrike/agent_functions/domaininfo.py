from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class DomaininfoArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class DomaininfoCommand(CommandBase):
    cmd = "domaininfo"
    needs_admin = False
    help_cmd = "domaininfo"
    description = "Query the machine's hostname, DNS domain, FQDN, OS version, and workgroup via GetComputerNameExA and NetWkstaGetInfo."
    version = 2
    author = "@Lavender-exe"
    attackmapping = ["T1082"]
    argument_class = DomaininfoArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        dependencies=["inline_execute"],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        args = [("string", "(objectCategory=domainDNS)"), ("string", "")]
        return await bof_tasking(taskData, "es_ldapsearch.x64.o", coff_arguments=args)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
