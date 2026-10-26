from mythic_container.MythicCommandBase import *


class JobkillArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="job_id",
                type=ParameterType.Number,
                description="Job ID to kill (from jobs output)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("job_id", int(self.command_line.strip()))


class JobkillCommand(CommandBase):
    cmd = "jobkill"
    needs_admin = False
    help_cmd = "jobkill <job_id>"
    description = "Kill a running background job by its ID."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = JobkillArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = f"job #{taskData.args.get_arg('job_id')}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
