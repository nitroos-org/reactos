/* mshtmlrender.exe <outfile> : creates an mshtml HTMLDocument, writes a page, lets Gecko lay it out and run its script,
 * and records what it reads back. Exit 0 = the page rendered and its script ran, 1 = not. Needs Wine Gecko. */
#define COBJMACROS
#include <windows.h>
#include <ole2.h>
#include <mshtml.h>
#include <stdio.h>

static const GUID CLSID_HTMLDoc = {0x25336920,0x03f9,0x11cf,{0x8f,0xd0,0x00,0xaa,0x00,0x68,0x6f,0x13}};
static FILE *out;
static void pump(DWORD ms)
{
    DWORD end = GetTickCount() + ms;
    MSG m;
    while ((LONG)(end - GetTickCount()) > 0)
    {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
        Sleep(20);
    }
}
static void put(const char *what, BSTR b)
{
    fprintf(out, "%s=", what);
    if (b) fprintf(out, "%ls", b);
    fprintf(out, "\n");
}
/* a crash must not leave a "stopped working" box that blocks an unattended test: record where, and exit 3 */
static LONG WINAPI crash(EXCEPTION_POINTERS *ep)
{
    HMODULE mod = NULL;
    char name[MAX_PATH] = "?";
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)ep->ExceptionRecord->ExceptionAddress, &mod);
    if (mod) GetModuleFileNameA(mod, name, sizeof(name));
    if (out)
    {
        fprintf(out, "CRASH code=%08lx addr=%p module=%s base=%p\nRENDER:FAIL crash\n", (unsigned long)ep->ExceptionRecord->ExceptionCode,
                ep->ExceptionRecord->ExceptionAddress, name, (void *)mod);
        fflush(out);
    }
    ExitProcess(3);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char **argv)
{
    IHTMLDocument2 *doc = NULL;
    IHTMLDocument3 *doc3 = NULL;
    IHTMLElement *el = NULL, *body = NULL;
    SAFEARRAY *sa;
    VARIANT *v;
    BSTR html, s = NULL;
    HRESULT hr;
    LONG w = 0, h = 0;
    int ok = 0;
#ifdef _WIN64
    const char *arch = "x64";
#else
    const char *arch = "x86";
#endif

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    SetUnhandledExceptionFilter(crash);
    out = fopen(argc > 1 ? argv[1] : "mshtmlrender.txt", "w");
    if (!out) return 2;
    fprintf(out, "arch=%s\n", arch);
    CoInitialize(NULL);
    hr = CoCreateInstance(&CLSID_HTMLDoc, NULL, CLSCTX_INPROC_SERVER, &IID_IHTMLDocument2, (void **)&doc);
    fprintf(out, "create=%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) goto done;
    html = SysAllocString(L"<html><head><title>GeckoRenderTest</title></head><body>"
                          L"<div id=d style='width:200px;height:50px;background:#c00'>before</div>"
                          L"<script>document.getElementById('d').innerText='script ran';</script></body></html>");
    sa = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    SafeArrayAccessData(sa, (void **)&v);
    V_VT(v) = VT_BSTR; V_BSTR(v) = html;
    SafeArrayUnaccessData(sa);
    hr = IHTMLDocument2_write(doc, sa);
    fprintf(out, "write=%08lx\n", (unsigned long)hr);
    IHTMLDocument2_close(doc);
    SafeArrayDestroy(sa);
    pump(4000);
    if (SUCCEEDED(IHTMLDocument2_get_readyState(doc, &s))) { put("readyState", s); SysFreeString(s); s = NULL; }
    if (SUCCEEDED(IHTMLDocument2_get_title(doc, &s))) { put("title", s); if (s && !wcscmp(s, L"GeckoRenderTest")) ok |= 1; SysFreeString(s); s = NULL; }
    if (SUCCEEDED(IHTMLDocument2_get_body(doc, &body)) && body)
    {
        if (SUCCEEDED(IHTMLElement_get_innerText(body, &s))) { put("bodyText", s); if (s && wcsstr(s, L"script ran")) ok |= 2; SysFreeString(s); s = NULL; }
        IHTMLElement_Release(body);
    }
    if (SUCCEEDED(IHTMLDocument2_QueryInterface(doc, &IID_IHTMLDocument3, (void **)&doc3)))
    {
        BSTR id = SysAllocString(L"d");
        if (SUCCEEDED(IHTMLDocument3_getElementById(doc3, id, &el)) && el)
        {
            IHTMLElement_get_offsetWidth(el, &w);
            IHTMLElement_get_offsetHeight(el, &h);
            IHTMLElement_Release(el);
        }
        SysFreeString(id);
        IHTMLDocument3_Release(doc3);
    }
    fprintf(out, "layout=%ldx%ld\n", w, h);
    if (w == 200 && h == 50) ok |= 4;
done:
    if (doc) IHTMLDocument2_Release(doc);
    fprintf(out, "RENDER:%s ok=%d\n", ok == 7 ? "PASS" : "FAIL", ok);
    fclose(out);
    CoUninitialize();
    return ok == 7 ? 0 : 1;
}
