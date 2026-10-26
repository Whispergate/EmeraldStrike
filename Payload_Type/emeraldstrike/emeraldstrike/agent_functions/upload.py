from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import base64


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="File to upload to the target",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="remote_path",
                type=ParameterType.String,
                description="Destination path on target",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(UploadCommand.help_cmd))


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload -file <file> -remote_path <path>"
    description = "Upload a file to the target"
    version = 1
    supported_ui_features = ["file_browser:upload"]
    author = "@Lavender-exe"
    attackmapping = ["T1105"]
    argument_class = UploadArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=taskData.args.get_arg("file"),
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get file: {file_content.Error}"
            return response
        taskData.args.add_arg("file_data", base64.b64encode(file_content.Content).decode(), ParameterType.String)
        response.DisplayParams = f"{taskData.args.get_arg('remote_path')} ({len(file_content.Content)} bytes)"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
