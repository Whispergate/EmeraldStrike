from mythic_container.MythicCommandBase import *


class MakeTokenArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                description="Domain for logon (use . for local)",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=3)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split(None, 2)
            if len(parts) == 3:
                self.add_arg("domain", parts[0])
                self.add_arg("username", parts[1])
                self.add_arg("password", parts[2])
            elif len(parts) == 2 and "\\" in parts[0]:
                dom, user = parts[0].split("\\", 1)
                self.add_arg("domain", dom)
                self.add_arg("username", user)
                self.add_arg("password", parts[1])
            else:
                raise Exception("Usage: make_token DOMAIN\\user password  or  make_token <domain> <user> <pass>")


class MakeTokenCommand(CommandBase):
    cmd = "make_token"
    needs_admin = False
    help_cmd = "make_token DOMAIN\\user password"
    description = "Create a new logon token with the specified credentials and impersonate it."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.003"]
    argument_class = MakeTokenArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        domain = taskData.args.get_arg("domain")
        username = taskData.args.get_arg("username")
        response.DisplayParams = f"{domain}\\{username}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
