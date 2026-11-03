from mythic_container.MythicCommandBase import *
import json


class UnlinkArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="link_info",
                cli_name="Callback",
                display_name="Callback to Unlink",
                type=ParameterType.LinkInfo,
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob.")
        self.load_args_from_json_string(self.command_line)


class UnlinkCommand(CommandBase):
    cmd = "unlink"
    needs_admin = False
    help_cmd = "unlink (modal popup)"
    description = "Disconnect from a linked P2P beacon."
    version = 2
    supported_ui_features = ["callback_table:unlink"]
    author = "@Lavender-exe"
    attackmapping = ["T1021.002"]
    argument_class = UnlinkArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        # Pass link_info through to the translator, which extracts
        # callback_uuid for the agent to identify the peer.
        link_info = taskData.args.get_arg("link_info")
        callback_uuid = link_info.get("callback_uuid", "")
        host = link_info.get("host", callback_uuid)
        response.DisplayParams = host
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
