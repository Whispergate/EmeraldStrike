from mythic_container.MythicCommandBase import *
import json


class LinkArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="connection_info",
                cli_name="NewConnection",
                type=ParameterType.ConnectionInfo,
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Link command requires arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob of arguments.")
        self.load_args_from_json_string(self.command_line)


class LinkCommand(CommandBase):
    cmd = "link"
    needs_admin = False
    help_cmd = "link"
    description = (
        "Link to an SMB beacon on a remote host via named pipe for P2P communication. "
        "Select a payload or existing callback from the link dialog."
    )
    version = 2
    supported_ui_features = ["callback_table:link"]
    author = "@Lavender-exe"
    attackmapping = ["T1570", "T1572", "T1021.002"]
    argument_class = LinkArguments
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
        # Pass connection_info through to the translator, which extracts
        # host + pipename from the nested c2_profile parameters.
        connection_info = taskData.args.get_arg("connection_info")
        host = connection_info.get("host", ".")
        c2_profile = connection_info.get("c2_profile", {})
        c2_params = c2_profile.get("parameters", {})
        pipename = c2_params.get("pipename", "")
        if not pipename:
            response.Success = False
            response.Error = "No pipename found in c2 profile parameters"
            return response
        response.DisplayParams = f"\\{host}\\pipe\\{pipename}"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
