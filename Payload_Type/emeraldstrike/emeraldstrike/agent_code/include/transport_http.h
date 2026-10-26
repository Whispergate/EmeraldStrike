#ifndef EMERALDSTRIKE_TRANSPORT_HTTP_H
#define EMERALDSTRIKE_TRANSPORT_HTTP_H

#include "common.h"

BOOL http_checkin(PINSTANCE inst);
BOOL http_get_tasks(PINSTANCE inst, BYTE** tasks, DWORD* tasks_len);
BOOL http_post_response(PINSTANCE inst, BYTE* data, DWORD data_len, BYTE** response, DWORD* resp_len);

#endif
