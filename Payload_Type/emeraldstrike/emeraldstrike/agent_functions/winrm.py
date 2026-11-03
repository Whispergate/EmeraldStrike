import shlex

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class WinrmArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Remote host (WS-Man listener on port 5985)",
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to run on the remote host (via cmd.exe /c)",
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Optional: username for BASIC auth (empty = current token, NEGOTIATE)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Optional: password for BASIC auth",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
            return
        # winrm <host> <command> [user] [pass]
        try:
            tokens = shlex.split(self.command_line)
        except ValueError:
            tokens = self.command_line.split()
        if len(tokens) < 2:
            raise ValueError("usage: winrm <host> <command> [user] [pass]")
        self.add_arg("host", tokens[0])
        if len(tokens) >= 4:
            # trailing "user pass" detected; command is the quoted middle token(s)
            self.add_arg("command", " ".join(tokens[1:-2]))
            self.add_arg("username", tokens[-2])
            self.add_arg("password", tokens[-1])
        elif len(tokens) == 3:
            # ambiguous: treat middle+last as command continuation (no creds)
            self.add_arg("command", " ".join(tokens[1:]))
        else:
            self.add_arg("command", tokens[1])


class WinrmCommand(CommandBase):
    cmd = "winrm"
    needs_admin = False
    help_cmd = "winrm <host> <command> [user] [pass]"
    description = "Run a command on a remote host over WinRM/WS-Management (HTTP 5985)"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1021.006"]
    argument_class = WinrmArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("host") + " " + taskData.args.get_arg("command")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
