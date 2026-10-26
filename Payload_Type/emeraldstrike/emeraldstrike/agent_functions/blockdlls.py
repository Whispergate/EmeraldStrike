from mythic_container.MythicCommandBase import *


class BlockdllsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                description="Enable or disable non-Microsoft DLL blocking in child processes",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("action", self.command_line.strip())


class BlockdllsCommand(CommandBase):
    cmd = "blockdlls"
    needs_admin = False
    help_cmd = "blockdlls start  |  blockdlls stop"
    description = "Block non-Microsoft DLLs from loading in child processes spawned by the agent."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1562.001"]
    argument_class = BlockdllsArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("action")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
