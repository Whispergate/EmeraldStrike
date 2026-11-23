import struct
import base64
import pathlib
from mythic_container.MythicCommandBase import *

BOF_DIR = pathlib.Path(__file__).resolve().parent.parent / "bof_files"


async def load_bof(filename: str) -> bytes:
    """Load a BOF .o file from the bof_files directory."""
    path = BOF_DIR / filename
    if not path.exists():
        raise Exception(f"BOF file not found: {path}")
    return path.read_bytes()


async def bof_tasking(
    task: PTTaskMessageAllData,
    bof_filename: str,
    coff_arguments: list = None,
) -> PTTaskCreateTaskingMessageResponse:
    """Redirect a command to inline_execute with an embedded BOF.

    Loads the BOF .o from disk, base64-encodes it, packs any arguments
    in CS bof_pack format, and returns a response that Mythic delivers
    as an inline_execute task to the agent.

    coff_arguments: list of (type_str, value) tuples.
        type_str is one of: "int16", "int32", "string", "wchar".
    """
    bof_bytes = await load_bof(bof_filename)

    task.args.add_arg("bof_name", bof_filename, type=ParameterType.String)
    task.args.add_arg(
        "bof_data",
        base64.b64encode(bof_bytes).decode(),
        type=ParameterType.String,
    )

    packed = b""
    if coff_arguments:
        for arg_type, value in coff_arguments:
            if arg_type == "int16":
                packed += struct.pack("<H", int(value) & 0xFFFF)
            elif arg_type == "int32":
                packed += struct.pack("<I", int(value) & 0xFFFFFFFF)
            elif arg_type == "string":
                encoded = (str(value) + "\x00").encode("utf-8")
                packed += struct.pack("<I", len(encoded)) + encoded
            elif arg_type == "wchar":
                encoded = (str(value) + "\x00").encode("utf-16_le")
                packed += struct.pack("<I", len(encoded)) + encoded

    task.args.add_arg(
        "bof_args",
        base64.b64encode(packed).decode(),
        type=ParameterType.String,
    )
    task.args.add_arg("fork_and_run_int", 0, type=ParameterType.Number)

    return PTTaskCreateTaskingMessageResponse(
        TaskID=task.Task.ID,
        CommandName="inline_execute",
        TokenID=task.Task.TokenID,
    )
