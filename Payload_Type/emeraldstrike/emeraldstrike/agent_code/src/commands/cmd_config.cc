#include "config.h"
#ifdef INCLUDE_CMD_CONFIG

#include "commands.h"

static void int_to_str(DWORD val, char* buf) {
    if (val == 0) { buf[0] = '0'; buf[1] = 0; return; }
    char tmp[16]; int i = 0;
    while (val > 0) { tmp[i++] = '0' + (val % 10); val /= 10; }
    for (int j = 0; j < i; j++) buf[j] = tmp[i - 1 - j];
    buf[i] = 0;
}

VOID cmd_config(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD action_len = 0;
    char* action = parser_string(args, &action_len);

    if (!action || action_len == 0 || (action[0] == 'g' || action[0] == 'v')) {
        // get/view - dump current config
        char line[1024] = {0};
        int pos = 0;

        // UUID
        xstr(lbl1, "uuid: ");
        for (int i = 0; lbl1[i]; i++) line[pos++] = lbl1[i];
        for (int i = 0; i < 36 && inst->Config.uuid[i]; i++) line[pos++] = inst->Config.uuid[i];
        line[pos++] = '\n';

        // Sleep
        xstr(lbl2, "sleep: ");
        for (int i = 0; lbl2[i]; i++) line[pos++] = lbl2[i];
        char numstr[16] = {0};
        int_to_str(inst->Config.sleep_ms, numstr);
        for (int i = 0; numstr[i]; i++) line[pos++] = numstr[i];
        xstr(ms, "ms\n");
        for (int i = 0; ms[i]; i++) line[pos++] = ms[i];

        // Jitter
        xstr(lbl3, "jitter: ");
        for (int i = 0; lbl3[i]; i++) line[pos++] = lbl3[i];
        es_memset(numstr, 0, 16);
        int_to_str(inst->Config.jitter, numstr);
        for (int i = 0; numstr[i]; i++) line[pos++] = numstr[i];
        xstr(pct, "%\n");
        for (int i = 0; pct[i]; i++) line[pos++] = pct[i];

        // Killdate
        xstr(lbl4, "killdate: ");
        for (int i = 0; lbl4[i]; i++) line[pos++] = lbl4[i];
        es_memset(numstr, 0, 16);
        int_to_str(inst->Config.killdate, numstr);
        for (int i = 0; numstr[i]; i++) line[pos++] = numstr[i];
        line[pos++] = '\n';

        package_add_bytes(inst, response, (BYTE*)line, pos);
    } else if (action[0] == 's') {
        // set - parse key=value
        DWORD key_len = 0, val_len = 0;
        char* key = parser_string(args, &key_len);
        DWORD newval = parser_int32(args);

        if (!key || key_len == 0) {
            package_add_string(inst, response, XSTR("Usage: config set <sleep|jitter|killdate> <value>"));
            response->is_error = TRUE;
            return;
        }

        if (key[0] == 's') {
            inst->Config.sleep_ms = newval;
            package_add_string(inst, response, XSTR("Sleep updated"));
        } else if (key[0] == 'j') {
            inst->Config.jitter = newval;
            package_add_string(inst, response, XSTR("Jitter updated"));
        } else if (key[0] == 'k') {
            inst->Config.killdate = newval;
            package_add_string(inst, response, XSTR("Killdate updated"));
        } else {
            package_add_string(inst, response, XSTR("Unknown config key"));
            response->is_error = TRUE;
        }
    }
}

#endif
