from mythic_container.MythicCommandBase import *


class DownloadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File path to download from target",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line)


class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download <filepath>"
    description = "Download a file from the target"
    version = 1
    supported_ui_features = ["file_browser:download"]
    author = "@Lavender-exe"
    attackmapping = ["T1041"]
    argument_class = DownloadArguments
    browser_script = BrowserScript(script_name="download", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
