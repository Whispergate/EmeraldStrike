#include "config.h"
#ifdef INCLUDE_CMD_BLOCKDLLS

#include "commands.h"
#include "common.h"

// blockdlls <action>: enable/disable blocking of non-Microsoft DLLs for
// processes spawned by the agent (CIG - ProcessMitigationPolicy binary signature).
// Consumed by cmd_spawn/cmd_shell via UpdateProcThreadAttribute.
VOID cmd_blockdlls(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD action_len = 0;
    char* action = parser_string(args, &action_len);
    if (!action || action_len == 0) {
        package_add_string(inst, response, XSTR("blockdlls is currently disabled"));
        inst->BlockDlls = FALSE;
        return;
    }

    // "block" enables, anything else disables
    if (action_len == 5 &&
        (action[0] | 0x20) == 'b' && (action[1] | 0x20) == 'l' &&
        (action[2] | 0x20) == 'o' && (action[3] | 0x20) == 'c' &&
        (action[4] | 0x20) == 'k') {
        inst->BlockDlls = TRUE;
        package_add_string(inst, response, XSTR("blockdlls is currently enabled"));
    } else {
        inst->BlockDlls = FALSE;
        package_add_string(inst, response, XSTR("blockdlls is currently disabled"));
    }
}

#endif
