#ifndef EMERALDSTRIKE_STACKSTR_H
#define EMERALDSTRIKE_STACKSTR_H

#define STK_ADVAPI32(v)     xstr(v, "advapi32.dll")
#define STK_BCRYPT(v)       xstr(v, "bcrypt.dll")
#define STK_WINHTTP(v)      xstr(v, "winhttp.dll")
#define STK_WININET(v)      xstr(v, "wininet.dll")
#define STK_IPHLPAPI(v)     xstr(v, "iphlpapi.dll")
#define STK_AMSI(v)         xstr(v, "amsi.dll")
#define STK_NETAPI32(v)     xstr(v, "netapi32.dll")
#define STK_USER32(v)       xstr(v, "user32.dll")
#define STK_WS2_32(v)       xstr(v, "ws2_32.dll")

#endif
