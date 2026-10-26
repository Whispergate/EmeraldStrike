from mythic_container.MythicCommandBase import *


class PpidArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="PID to use as parent for child processes. Set to 0 to clear.",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("pid", int(self.command_line.strip()))


class PpidCommand(CommandBase):
    cmd = "ppid"
    needs_admin = False
    help_cmd = "ppid <pid>  |  ppid 0"
    description = "Set the parent PID for child processes. Spawned processes will appear as children of the specified PID. Use 0 to reset."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.004"]
    argument_class = PpidArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        pid = taskData.args.get_arg("pid")
        response.DisplayParams = str(pid) if pid else "reset"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
