from mythic_container.MythicCommandBase import *


class StatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="path", type=ParameterType.String, description="File path", parameter_group_info=[ParameterGroupInfo(required=True)]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line if self.command_line else "")


class StatCommand(CommandBase):
    cmd = "stat"
    needs_admin = False
    help_cmd = "stat <path>"
    description = "Get file metadata: size, attributes (hidden/system/readonly/archive), and created/modified/accessed timestamps."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1083"]
    argument_class = StatArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="stat", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
