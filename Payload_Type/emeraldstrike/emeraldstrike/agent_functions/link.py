from mythic_container.MythicCommandBase import *


class LinkArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Target host to connect to via SMB named pipe",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="pipename",
                type=ParameterType.String,
                description="Named pipe name",
                default_value="emeraldstrike",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            self.add_arg("host", parts[0])
            if len(parts) > 1:
                self.add_arg("pipename", parts[1])


class LinkCommand(CommandBase):
    cmd = "link"
    needs_admin = False
    help_cmd = "link <host> [pipename]"
    description = "Connect to an SMB beacon on a target host via named pipe for P2P communication."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1071.002"]
    argument_class = LinkArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        host = taskData.args.get_arg("host")
        pipe = taskData.args.get_arg("pipename")
        response.DisplayParams = f"\\\\{host}\\pipe\\{pipe}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
