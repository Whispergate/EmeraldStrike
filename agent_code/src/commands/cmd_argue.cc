#include "config.h"
#ifdef INCLUDE_CMD_ARGUE

#include "commands.h"
#include "common.h"

VOID cmd_argue(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD action_len = 0;
    char* action = parser_string(args, &action_len);
    DWORD fake_len = 0;
    char* fake_args = parser_string(args, &fake_len);

    if (!action || action_len == 0) {
        package_add_string(inst, response, "no action specified");
        response->is_error = TRUE;
        return;
    }

    xstr(_set, "set");
    xstr(_clr, "clear");

    if (es_strcmp(action, _set) == 0) {
        if (!fake_args || fake_len == 0) {
            package_add_string(inst, response, "no arguments to set");
            response->is_error = TRUE;
            return;
        }

        if (inst->argue_args) {
            es_free(inst, inst->argue_args);
        }
        inst->argue_args = (char*)es_malloc(inst, fake_len + 1);
        if (!inst->argue_args) {
            package_add_string(inst, response, "allocation failed");
            response->is_error = TRUE;
            return;
        }
        es_memcpy(inst->argue_args, fake_args, fake_len);
        inst->argue_args[fake_len] = '\0';
        inst->argue_len = fake_len;

        package_add_string(inst, response, "argue set");
    } else if (es_strcmp(action, _clr) == 0) {
        if (inst->argue_args) {
            es_free(inst, inst->argue_args);
            inst->argue_args = NULL;
            inst->argue_len = 0;
        }
        package_add_string(inst, response, "argue cleared");
    } else {
        package_add_string(inst, response, "unknown action (use set or clear)");
        response->is_error = TRUE;
    }
}

#endif
