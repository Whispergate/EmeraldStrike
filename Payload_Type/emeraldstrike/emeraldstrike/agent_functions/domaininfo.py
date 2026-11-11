from mythic_container.MythicCommandBase import *


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
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1082"]
    argument_class = DomaininfoArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="domaininfo", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
