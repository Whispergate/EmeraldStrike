#include "config.h"
#include "commands.h"

#ifdef INCLUDE_CMD_SPAWNTO_X64

VOID cmd_spawnto_x64(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD app_len = 0;
    char* application = (char*)parser_string(args, &app_len);
    if (!application || app_len == 0) {
        package_add_string(inst, response, XSTR("no application path"));
        response->is_error = TRUE;
        return;
    }

    DWORD copy_len = app_len < 259 ? app_len : 259;
    es_memcpy(inst->Spawnto.x64, application, copy_len);
    inst->Spawnto.x64[copy_len] = '\0';

    DWORD args_len = 0;
    char* arguments = (char*)parser_string(args, &args_len);
    if (arguments && args_len > 0) {
        DWORD args_copy = args_len < 259 ? args_len : 259;
        es_memcpy(inst->Spawnto.x64_args, arguments, args_copy);
        inst->Spawnto.x64_args[args_copy] = '\0';
    } else {
        inst->Spawnto.x64_args[0] = '\0';
    }

    char msg[600];
    es_memset(msg, 0, sizeof(msg));
    xstr(_pfx, "spawnto_x64 set to: ");
    DWORD i = 0;
    while (_pfx[i] && i < 500) { msg[i] = _pfx[i]; i++; }
    DWORD j = 0;
    while (inst->Spawnto.x64[j] && i < 598) { msg[i++] = inst->Spawnto.x64[j++]; }
    if (inst->Spawnto.x64_args[0]) {
        msg[i++] = ' ';
        j = 0;
        while (inst->Spawnto.x64_args[j] && i < 598) { msg[i++] = inst->Spawnto.x64_args[j++]; }
    }
    msg[i] = '\0';

    package_add_string(inst, response, msg);
}

#endif

#ifdef INCLUDE_CMD_SPAWNTO_X86

VOID cmd_spawnto_x86(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD app_len = 0;
    char* application = (char*)parser_string(args, &app_len);
    if (!application || app_len == 0) {
        package_add_string(inst, response, XSTR("no application path"));
        response->is_error = TRUE;
        return;
    }

    DWORD copy_len = app_len < 259 ? app_len : 259;
    es_memcpy(inst->Spawnto.x86, application, copy_len);
    inst->Spawnto.x86[copy_len] = '\0';

    DWORD args_len = 0;
    char* arguments = (char*)parser_string(args, &args_len);
    if (arguments && args_len > 0) {
        DWORD args_copy = args_len < 259 ? args_len : 259;
        es_memcpy(inst->Spawnto.x86_args, arguments, args_copy);
        inst->Spawnto.x86_args[args_copy] = '\0';
    } else {
        inst->Spawnto.x86_args[0] = '\0';
    }

    char msg[600];
    es_memset(msg, 0, sizeof(msg));
    xstr(_pfx, "spawnto_x86 set to: ");
    DWORD i = 0;
    while (_pfx[i] && i < 500) { msg[i] = _pfx[i]; i++; }
    DWORD j = 0;
    while (inst->Spawnto.x86[j] && i < 598) { msg[i++] = inst->Spawnto.x86[j++]; }
    if (inst->Spawnto.x86_args[0]) {
        msg[i++] = ' ';
        j = 0;
        while (inst->Spawnto.x86_args[j] && i < 598) { msg[i++] = inst->Spawnto.x86_args[j++]; }
    }
    msg[i] = '\0';

    package_add_string(inst, response, msg);
}

#endif
