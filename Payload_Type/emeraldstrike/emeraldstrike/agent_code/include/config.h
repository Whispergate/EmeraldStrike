#ifndef EMERALDSTRIKE_CONFIG_H
#define EMERALDSTRIKE_CONFIG_H

// Transport selection - stamped by builder
%TRANSPORT_DEFINE%

// Serialized C2 config blob - stamped by builder
static const unsigned char CONFIG_BYTES[] = { %CONFIG_BYTES% };

// Command selection - stamped by builder
%COMMAND_DEFINES%

// Evasion options - stamped by builder
%EVASION_DEFINES%

// Sleepmask COFF data - stamped by builder (UDRL mode only)
%SLEEPMASK_COFF_DEFINE%

// CLR bootstrap PIC shellcode for fork-and-run execute_assembly
// Compiled from src/evasion/clr_bootstrap.cc and stamped by builder
%CLR_BOOTSTRAP_DEFINE%

// BOF bootstrap PIC shellcode for fork-and-run inline_execute
// Compiled from src/evasion/bof_bootstrap.cc and stamped by builder
%BOF_BOOTSTRAP_DEFINE%

// Sleep mask type constants
#define MASK_NONE    0
#define MASK_DEFAULT 1
#define MASK_EKKO    2
#define MASK_UDRL    3

// Beacon Gate - enable to route Win32 calls through sleepmask (requires MASK_UDRL)
#ifndef BEACON_GATE_ENABLED
#define BEACON_GATE_ENABLED 0
#endif

// Injection technique constants
#define INJECT_CRT     0
#define INJECT_APC     1
#define INJECT_SECTION 2
#define INJECT_CUSTOM  3
#define INJECT_CASCADE 5
#define INJECT_HELLSHALL 4

#ifndef INJECTION_TECHNIQUE
#define INJECTION_TECHNIQUE INJECT_CRT
#endif

// Callstack spoofing mode constants
#define SPOOF_NONE    0
#define SPOOF_WMI     1
#define SPOOF_RPC     2
#define SPOOF_CUSTOM  3

#ifndef CALLSTACK_SPOOF_MODE
#define CALLSTACK_SPOOF_MODE SPOOF_NONE
#endif

// Command macros
// #define INCLUDE_CMD_SHELL
// #define INCLUDE_CMD_LS
// #define INCLUDE_CMD_CD
// #define INCLUDE_CMD_PWD
// #define INCLUDE_CMD_CAT
// #define INCLUDE_CMD_UPLOAD
// #define INCLUDE_CMD_DOWNLOAD
// #define INCLUDE_CMD_EXIT
// #define INCLUDE_CMD_SLEEP
// #define INCLUDE_CMD_WHOAMI
// #define INCLUDE_CMD_GETUID
// #define INCLUDE_CMD_PS
// #define INCLUDE_CMD_KILL
// #define INCLUDE_CMD_CP
// #define INCLUDE_CMD_MV
// #define INCLUDE_CMD_RM
// #define INCLUDE_CMD_MKDIR
// #define INCLUDE_CMD_INLINE_EXECUTE
// #define INCLUDE_CMD_INJECT
// #define INCLUDE_CMD_CONFIG
// #define INCLUDE_CMD_SPAWNTO_X64
// #define INCLUDE_CMD_SPAWNTO_X86
// #define INCLUDE_CMD_SPAWN
// #define INCLUDE_CMD_ARGUE
// #define INCLUDE_CMD_EXECUTE_ASSEMBLY
// #define INCLUDE_CMD_POWERPICK
// #define INCLUDE_CMD_SCREENSHOT
// #define INCLUDE_CMD_RUN
// #define INCLUDE_CMD_EXECUTE
// #define INCLUDE_CMD_MAKE_TOKEN
// #define INCLUDE_CMD_STEAL_TOKEN
// #define INCLUDE_CMD_REV2SELF
// #define INCLUDE_CMD_GETPRIVS
// #define INCLUDE_CMD_PPID
// #define INCLUDE_CMD_BLOCKDLLS


// QoL commands (A+B+C+D batch, 2026-11-08)
// #define INCLUDE_CMD_ENV
// #define INCLUDE_CMD_DRIVERS
// #define INCLUDE_CMD_TASKS
// #define INCLUDE_CMD_SERVICES
// #define INCLUDE_CMD_SOFTWARE
// #define INCLUDE_CMD_NETSTAT
// #define INCLUDE_CMD_ARP
// #define INCLUDE_CMD_ROUTE
// #define INCLUDE_CMD_LOCALGROUP
// #define INCLUDE_CMD_SHARE
// #define INCLUDE_CMD_DOMAININFO
// #define INCLUDE_CMD_UAC
// #define INCLUDE_CMD_DEFENDER
// #define INCLUDE_CMD_WINDOWLIST
// #define INCLUDE_CMD_UPTIME
// #define INCLUDE_CMD_QUSER
// #define INCLUDE_CMD_FIND
// #define INCLUDE_CMD_GREP
// #define INCLUDE_CMD_TREE
// #define INCLUDE_CMD_STAT
// #define INCLUDE_CMD_TIMESTOMP
// #define INCLUDE_CMD_WGET
// #define INCLUDE_CMD_PSGREP
// #define INCLUDE_CMD_PROCINFO
// #define INCLUDE_CMD_CLIPBOARD
// #define INCLUDE_CMD_PING
// #define INCLUDE_CMD_DNS
// #define INCLUDE_CMD_PORTSCAN
// #define INCLUDE_CMD_CURL

// Callstack-spoof verification command: only present when spoofing itself is
// enabled (it is useless otherwise and would be an artifact in default builds)
#if defined(CALLSTACK_SPOOF_MODE) && (CALLSTACK_SPOOF_MODE != SPOOF_NONE)
// #define INCLUDE_CMD_SPOOF_TEST
#endif

#endif // EMERALDSTRIKE_CONFIG_H
