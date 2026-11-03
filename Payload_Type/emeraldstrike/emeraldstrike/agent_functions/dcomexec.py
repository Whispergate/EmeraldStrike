from mythic_container.MythicCommandBase import *


class DcomexecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Remote hostname or IP to execute on via DCOM (MMC20.Application)",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to run on the remote host (cmd.exe /c is prepended)",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split(None, 1)
            if len(parts) < 2:
                raise Exception("Usage: dcomexec <host> <command>")
            self.add_arg("host", parts[0])
            self.add_arg("command", parts[1])


class DcomexecCommand(CommandBase):
    cmd = "dcomexec"
    needs_admin = False
    help_cmd = "dcomexec <host> <command>"
    description = "Lateral movement: run a command on a remote host via MMC20.Application DCOM ExecuteShellCommand. Fire-and-forget, no output capture."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1021.003"]
    argument_class = DcomexecArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        host = taskData.args.get_arg("host")
        command = taskData.args.get_arg("command")
        response.DisplayParams = f"{host} {command}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
