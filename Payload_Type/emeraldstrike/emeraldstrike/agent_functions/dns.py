from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class DnsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Hostname to resolve",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("hostname", self.command_line.strip())


class DnsCommand(CommandBase):
    cmd = "dns"
    needs_admin = False
    help_cmd = "dns [host]"
    description = "Resolve a hostname via getaddrinfo and list its addresses."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = DnsArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        dependencies=["inline_execute"],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = taskData.args.get_arg("hostname") or ""
        args = [("string", hostname), ("string", ""), ("int16", 1)]
        response = await bof_tasking(taskData, "es_nslookup.x64.o", coff_arguments=args)
        response.DisplayParams = hostname
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
