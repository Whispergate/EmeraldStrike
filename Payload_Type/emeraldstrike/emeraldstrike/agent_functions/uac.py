from mythic_container.MythicCommandBase import *


class UacArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class UacCommand(CommandBase):
    cmd = "uac"
    needs_admin = False
    help_cmd = "uac"
    description = "Query UAC policy from the registry: EnableLUA, ConsentPromptBehaviorAdmin, SecureUIAPaths, PromptOnSecureDesktop, and computed UAC level."
    version = 1
    author = "@Lavender-exe"
    attackmapping = ["T1548.002"]
    argument_class = UacArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="uac", author="@Lavender-exe", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
