from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RegisterBofArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                display_name="BOF File",
                type=ParameterType.File,
                description="Upload a BOF (.o COFF object file) to register for use with inline_execute",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON arguments.\n\tUsage: register_bof <file>")


class RegisterBofCommand(CommandBase):
    cmd = "register_bof"
    needs_admin = False
    help_cmd = "register_bof <bof.o>"
    description = (
        "Upload and register a BOF (.o COFF object file) in Mythic's file store. "
        "Registered BOFs appear in the inline_execute file picker for reuse."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = RegisterBofArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        script_only=True,
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

        file_id = taskData.args.get_arg("file")
        file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID,
            AgentFileID=file_id,
        ))
        if not file_search.Success or len(file_search.Files) == 0:
            response.Success = False
            response.Error = "Failed to find uploaded file"
            return response

        original_name = file_search.Files[0].Filename
        if not original_name.endswith(".o"):
            response.Success = False
            response.Error = f"Invalid file type: '{original_name}'. Expected .o"
            return response

        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to read file content: {file_content.Error}"
            return response

        reg_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
            TaskID=taskData.Task.ID,
            FileContents=file_content.Content,
            Filename=original_name,
            DeleteAfterFetch=False,
            IsScreenshot=False,
            IsDownloadFromAgent=False,
            Comment=f"Registered BOF: {original_name}",
        ))
        if not reg_resp.Success:
            response.Success = False
            response.Error = f"Failed to register BOF: {reg_resp.Error}"
            return response

        response.DisplayParams = f"{original_name} ({len(file_content.Content)} bytes)"
        response.Completed = True
        response.TaskStatus = "success"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
