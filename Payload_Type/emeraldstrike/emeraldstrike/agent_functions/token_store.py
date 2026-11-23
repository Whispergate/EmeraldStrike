from mythic_container.MythicCommandBase import *


class TokenStoreArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["list", "use", "remove"],
                default_value="list",
                description="Action: list stored tokens, use a token by ID, or remove a token by ID",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="id",
                type=ParameterType.Number,
                description="Token slot ID (0-7)",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            if len(parts) >= 1:
                self.add_arg("action", parts[0])
            if len(parts) >= 2:
                self.add_arg("id", int(parts[1]))


class TokenStoreCommand(CommandBase):
    cmd = "token_store"
    needs_admin = False
    help_cmd = "token_store list | token_store use <id> | token_store remove <id>"
    description = (
        "Manage an 8-slot persistent token store. Tokens are automatically "
        "stored when steal_token or make_token succeeds. Use 'list' to see "
        "stored tokens, 'use <id>' to activate one, 'remove <id>' to discard."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134"]
    argument_class = TokenStoreArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        token_id = taskData.args.get_arg("id")
        if action == "list":
            response.DisplayParams = "list"
        elif token_id is not None:
            response.DisplayParams = f"{action} {token_id}"
        else:
            response.DisplayParams = action
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
