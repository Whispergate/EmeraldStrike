from mythic_container.MythicCommandBase import *


class FindArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="path", type=ParameterType.String, description="Directory to search", parameter_group_info=[ParameterGroupInfo(required=True)]),
            CommandParameter(name="pattern", type=ParameterType.String, description="File pattern", parameter_group_info=[ParameterGroupInfo(required=False)]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line if self.command_line else "")


class FindCommand(CommandBase):
    cmd = "find"
    needs_admin = False
    help_cmd = "find <directory> [pattern]"
    description = "Recursively search a directory for files matching a wildcard pattern (e.g. *.docx). Max depth 10. Returns matching paths and sizes."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1083"]
    argument_class = FindArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="find", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
