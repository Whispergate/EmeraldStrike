#ifndef EMERALDSTRIKE_TRANSPORT_SMB_H
#define EMERALDSTRIKE_TRANSPORT_SMB_H

#include "common.h"

BOOL smb_start_server(PINSTANCE inst);
BOOL smb_read(PINSTANCE inst, BYTE** data, DWORD* data_len);
BOOL smb_write(PINSTANCE inst, BYTE* data, DWORD data_len);

#endif
