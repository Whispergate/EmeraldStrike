#include "config.h"
#ifdef INCLUDE_CMD_REV2SELF

#include "commands.h"
#include "common.h"

typedef BOOL (WINAPI *fn_RevertToSelf)(void);

// rev2self: drop impersonated token and return to the process identity
VOID cmd_rev2self(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_adv, "advapi32.dll");
    HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
    if (!h_adv) {
        package_add_string(inst, response, XSTR("advapi32 load failed"));
        response->is_error = TRUE;
        return;
    }
    fn_RevertToSelf pRevertToSelf = (fn_RevertToSelf)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("RevertToSelf")));
    if (!pRevertToSelf) {
        package_add_string(inst, response, XSTR("RevertToSelf resolve failed"));
        response->is_error = TRUE;
        return;
    }

    if (!pRevertToSelf()) {
        package_add_string(inst, response, XSTR("RevertToSelf failed"));
        response->is_error = TRUE;
        return;
    }

    if (inst->ImpersonationToken) {
        gate_CloseHandle(inst, inst->ImpersonationToken);
        inst->ImpersonationToken = NULL;
    }

    package_add_string(inst, response, XSTR("Token reverted"));
}

#endif
