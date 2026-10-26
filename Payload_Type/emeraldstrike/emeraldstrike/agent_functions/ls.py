from mythic_container.MythicCommandBase import *


class LsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                default_value=".",
                description="Directory path to list",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line if self.command_line else ".")


class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls [path]"
    description = "List directory contents"
    version = 1
    supported_ui_features = ["file_browser:list"]
    author = "@Lavender-exe"
    attackmapping = ["T1083"]
    argument_class = LsArguments
    browser_script = BrowserScript(script_name="ls", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
