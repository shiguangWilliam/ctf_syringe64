// tether_main.cpp —— 牵引 DLL: 双控制面(命名管道 + 本地 Web UI) + payload 追加 +
//                     冻结/解冻。管道名 \\.\pipe\syringe64-<pid>; Web UI 仅绑
//                     127.0.0.1, 端口 18700+pid%256, 页面内嵌。
//
// 命令行协议(两个控制面同构):
//   hello | modules | read <hexaddr> <len> | write <hexaddr> <hexbytes>
//   scan <module|*> "<pattern>" | scanrwx "<pattern>" | scanrange <s> <e> "<pattern>"
//   pe <hexbase> | export <hexbase> <name> | load <dll> | hooks | log
//   freeze | thaw | alloc <len> [exec] | free <addr> | cfgset <addr> | quit
// Web: GET /            -> 内嵌 dashboard
//      GET /api/exec?c=<urlencoded command> -> 同一命令面, 纯文本应答
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <string>

#include "syringe.hpp"
#include "core_exports.hpp"

#pragma comment(lib, "ws2_32.lib")

static HANDLE g_thread = nullptr;
static volatile LONG g_frozen = 0;

namespace syr { namespace detail { void log_line(const char* s); } }
static void tlog(const char* fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
  va_end(ap);
  syr::detail::log_line(buf);
}

// ---- payload 追加 -----------------------------------------------------------
static int LoadPayload(const std::wstring& path) {
  HMODULE h = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
  if (!h) { tlog("tether: LoadLibraryExW failed gle=%lu", GetLastError()); return -1; }
  auto init = (int(__cdecl*)(const syr::Api*))GetProcAddress(h, "SyrPayloadInit");
  if (!init) { tlog("tether: %ls loaded (no SyrPayloadInit export)", path.c_str()); return 0; }
  int r = init(SyrGetApi());
  tlog("tether: payload %ls init -> %d", path.c_str(), r);
  return r;
}

// ---- freeze / thaw ----------------------------------------------------------
static int ForEachOtherThread(bool suspend) {
  DWORD pid = GetCurrentProcessId();
  DWORD me = GetCurrentThreadId();
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return -1;
  THREADENTRY32 te{sizeof(te)};
  int n = 0;
  if (Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) continue;
      HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
      if (t) {
        if (suspend) { if (SuspendThread(t) != (DWORD)-1) n++; }
        else { if (ResumeThread(t) != (DWORD)-1) n++; }
        CloseHandle(t);
      }
    } while (Thread32Next(snap, &te));
  }
  CloseHandle(snap);
  return n;
}

// ---- SEH 安全读(__try 不能出现在带 C++ 对象展开的函数里) ---------------------
static bool SafeRead(uintptr_t addr, void* dst, size_t len) {
  __try { memcpy(dst, (const void*)addr, len); return true; }
  __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ============================================================================
// 命令处理(管道与 Web UI 共用)。返回完整应答文本(以单独 "." 行结束)。
// 返回空串表示命令为空; "BYE" 表示 quit。
// ============================================================================
static std::string HandleCommand(const char* line) {
  std::string reply;
  char arg1[512] = "", arg2[512] = "", arg3[512] = "";
  char cmd[64] = "";
  sscanf(line, "%63s %511s %511s %511s", cmd, arg1, arg2, arg3);

  if (!strcmp(cmd, "hello")) {
    char buf[256];
    _snprintf_s(buf, _TRUNCATE, "syringe64 tether v%d pid=%lu bits=64 web=http://127.0.0.1:%d\n.",
                SYR_VERSION, GetCurrentProcessId(), 18700 + (int)(GetCurrentProcessId() % 256));
    reply = buf;
  } else if (!strcmp(cmd, "modules")) {
    HMODULE mods[1024];
    DWORD need = 0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &need)) {
      int cnt = (int)(need / sizeof(HMODULE));
      for (int i = 0; i < cnt; i++) {
        wchar_t wn[512] = L"?";
        MODULEINFO mi{};
        GetModuleFileNameW(mods[i], wn, 512);
        GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi));
        char narrow[1200];
        _snprintf_s(narrow, _TRUNCATE, "%016llx %08llx %ls\n",
                    (unsigned long long)(uintptr_t)mods[i],
                    (unsigned long long)mi.SizeOfImage, wn);
        reply += narrow;
      }
      reply += ".";
    } else reply = "ERR enum\n.";
  } else if (!strcmp(cmd, "read")) {
    uintptr_t addr = _strtoui64(arg1, nullptr, 16);
    int len = atoi(arg2);
    if (!addr || len <= 0 || len > 2048) { reply = "ERR args\n."; return reply; }
    unsigned char tmp[2048];
    if (!SafeRead(addr, tmp, (size_t)len)) { reply = "ERR access\n."; return reply; }
    char hex[4096 + 1];
    for (int i = 0; i < len; i++) _snprintf_s(hex + i * 2, 3, _TRUNCATE, "%02X", tmp[i]);
    reply = hex; reply += "\n.";
  } else if (!strcmp(cmd, "write")) {
    uintptr_t addr = _strtoui64(arg1, nullptr, 16);
    size_t slen = strlen(arg2);
    if (!addr || slen == 0 || slen % 2 || slen > 2048) { reply = "ERR args\n."; return reply; }
    unsigned char tmp[1024];
    for (size_t i = 0; i < slen / 2; i++) {
      unsigned v; sscanf(arg2 + i * 2, "%2x", &v); tmp[i] = (unsigned char)v;
    }
    reply = SyrWriteMem(addr, tmp, slen / 2) == 0 ? "OK\n." : "ERR write\n.";
  } else if (!strcmp(cmd, "scan") || !strcmp(cmd, "scanrwx") ||
             !strcmp(cmd, "scanrange")) {
    char patbuf[512] = "";
    const char* q1 = strchr(line, '"');
    if (q1) {
      const char* q2 = strrchr(q1 + 1, '"');
      size_t pl = q2 ? (size_t)(q2 - q1 - 1) : strlen(q1 + 1);
      if (pl >= sizeof(patbuf)) pl = sizeof(patbuf) - 1;
      memcpy(patbuf, q1 + 1, pl);
      patbuf[pl] = 0;
    }
    if (!patbuf[0]) { reply = "ERR args\n."; return reply; }
    uintptr_t out[64];
    int nfound = -1;
    if (!strcmp(cmd, "scan")) {
      wchar_t mod[512] = L"";
      if (strcmp(arg1, "*") != 0) MultiByteToWideChar(CP_UTF8, 0, arg1, -1, mod, 512);
      nfound = SyrScanPattern(mod[0] ? mod : nullptr, patbuf, out, 64);
    } else if (!strcmp(cmd, "scanrwx")) {
      nfound = SyrScanRwx(patbuf, out, 64);
    } else {  // scanrange <start> <end> "<pattern>"
      uintptr_t s = _strtoui64(arg1, nullptr, 16);
      uintptr_t e = _strtoui64(arg2, nullptr, 16);
      if (!s || !e) { reply = "ERR args\n."; return reply; }
      nfound = SyrScanRange(s, e, patbuf, out, 64);
    }
    if (nfound < 0) { reply = "ERR scan\n."; return reply; }
    char buf[64];
    for (int i = 0; i < nfound; i++) {
      _snprintf_s(buf, _TRUNCATE, "%016llx", (unsigned long long)out[i]);
      reply += buf; reply += "\n";
    }
    reply += ".";
  } else if (!strcmp(cmd, "pe")) {
    uintptr_t b = _strtoui64(arg1, nullptr, 16);
    syr::SectionInfo secs[32] = {};
    int nsec = SyrPeSections(b, secs, 32);
    if (nsec < 0) { reply = "ERR pe\n."; return reply; }
    char l[256];
    for (int i = 0; i < nsec; i++) {
      _snprintf_s(l, _TRUNCATE, "%-8s %016llx %08llx exec=%d\n",
                  secs[i].name, (unsigned long long)secs[i].va,
                  (unsigned long long)secs[i].vsize, secs[i].exec);
      reply += l;
    }
    reply += ".";
  } else if (!strcmp(cmd, "export")) {
    uintptr_t b = _strtoui64(arg1, nullptr, 16);
    uintptr_t f = SyrPeExport(b, arg2);
    char l[64];
    _snprintf_s(l, _TRUNCATE, "%016llx\n.", (unsigned long long)f);
    reply = l;
  } else if (!strcmp(cmd, "load")) {
    wchar_t wpath[1024];
    MultiByteToWideChar(CP_UTF8, 0, arg1, -1, wpath, 1024);
    int r = LoadPayload(wpath);
    char buf[64];
    _snprintf_s(buf, _TRUNCATE, "LOAD %d\n.", r);
    reply = buf;
  } else if (!strcmp(cmd, "hooks")) {
    reply = SyrHooksInfo(); reply += "\n.";
  } else if (!strcmp(cmd, "log")) {
    reply = SyrGetLog();
    if (reply.empty() || reply.back() != '\n') reply += "\n";
    reply += ".";
  } else if (!strcmp(cmd, "freeze")) {
    int n = ForEachOtherThread(true);
    InterlockedExchange(&g_frozen, 1);
    char buf[64];
    _snprintf_s(buf, _TRUNCATE, "FROZEN %d\n.", n);
    reply = buf;
  } else if (!strcmp(cmd, "thaw")) {
    int n = ForEachOtherThread(false);
    InterlockedExchange(&g_frozen, 0);
    char buf[64];
    _snprintf_s(buf, _TRUNCATE, "THAWED %d\n.", n);
    reply = buf;
  } else if (!strcmp(cmd, "alloc")) {
    size_t sz = (size_t)_strtoui64(arg1, nullptr, 0);
    int exec = atoi(arg2);
    uintptr_t a = SyrAllocMem(sz ? sz : 0x1000, exec);
    char buf[64];
    if (!a) _snprintf_s(buf, _TRUNCATE, "ERR alloc\n.");
    else _snprintf_s(buf, _TRUNCATE, "%016llx\n.", (unsigned long long)a);
    reply = buf;
  } else if (!strcmp(cmd, "free")) {
    SyrFreeMem(_strtoui64(arg1, nullptr, 16));
    reply = "OK\n.";
  } else if (!strcmp(cmd, "cfgset")) {
    uintptr_t a = _strtoui64(arg1, nullptr, 16);
    char l[64];
    _snprintf_s(l, _TRUNCATE, "CFGSET %d base=%016llx\n.",
                SyrCfgBitmapSet(a), (unsigned long long)SyrCfgBitmapBase());
    reply = l;
  } else if (!strcmp(cmd, "quit")) {
    reply = "BYE\n.";
  } else if (!cmd[0]) {
    reply = "";
  } else {
    reply = "ERR unknown\n.";
  }
  return reply;
}

// ---- 命名管道服务 -----------------------------------------------------------
static DWORD WINAPI PipeServer(LPVOID) {
  wchar_t name[64];
  _snwprintf_s(name, _TRUNCATE, L"\\\\.\\pipe\\syringe64-%lu", GetCurrentProcessId());
  for (;;) {
    HANDLE pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX,
                                   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                   1, 8192, 8192, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 1;
    if (!ConnectNamedPipe(pipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
      CloseHandle(pipe);
      continue;
    }
    char line[2048];
    for (;;) {
      DWORD n = 0, got = 0;
      bool eof = false;
      while (n < sizeof(line) - 1) {
        char c;
        if (!ReadFile(pipe, &c, 1, &got, nullptr) || got == 0) { eof = true; break; }
        if (c == '\n' || c == '\r') { if (n == 0) continue; break; }
        line[n++] = c;
      }
      if (eof && n == 0) break;
      line[n] = 0;
      std::string reply = HandleCommand(line);
      if (!reply.empty()) {
        DWORD w = 0;
        WriteFile(pipe, reply.data(), (DWORD)reply.size(), &w, nullptr);
        FlushFileBuffers(pipe);
      }
      if (!strncmp(line, "quit", 4)) break;
      if (eof) break;
    }
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
  }
  return 0;
}

// ---- Web UI -----------------------------------------------------------------
static const char kDashboard[] =
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<title>syringe64</title><style>"
    "body{font:13px monospace;background:#111;color:#cde;margin:12px}"
    "h2{color:#8cf;margin:14px 0 4px}pre{background:#1b1b1b;border:1px solid #333;"
    "padding:6px;height:220px;overflow:auto;white-space:pre-wrap}"
    "input,button{font:13px monospace;background:#222;color:#cde;"
    "border:1px solid #444;padding:3px 6px}"
    "button{cursor:pointer}table{border-collapse:collapse}"
    "td,th{border:1px solid #333;padding:2px 8px;text-align:left}"
    ".cols{display:flex;gap:16px;flex-wrap:wrap}.cols>div{flex:1;min-width:380px}"
    "</style></head><body>"
    "<h1>syringe64 tether</h1><div class='cols'>"
    "<div><h2>status</h2><pre id='hello'></pre>"
    "<h2>hooks</h2><pre id='hooks'></pre></div>"
    "<div><h2>modules</h2><pre id='modules' style='height:290px'></pre></div>"
    "<div><h2>log (2s)</h2><pre id='log' style='height:290px'></pre></div>"
    "</div><h2>console</h2>"
    "<input id='cmd' size='60' placeholder='e.g. scan GameAssembly.dll &quot;48 89 5C&quot;'>"
    "<button onclick='run()'>exec</button> <button onclick='clr()'>clear</button>"
    "<pre id='out'></pre>"
    "<script>const $=id=>document.getElementById(id);"
    "async function ex(c){const r=await fetch('/api/exec?c='+encodeURIComponent(c));"
    "return r.text()}"
    "async function poll(){try{"
    "$('hello').textContent=await ex('hello');"
    "$('hooks').textContent=await ex('hooks');"
    "$('modules').textContent=await ex('modules');"
    "$('log').textContent=await ex('log');}catch(e){$('hello').textContent=''+e}}"
    "async function run(){const c=$('cmd').value;$('out').textContent='> '+c+" 
    "'\\n'+await ex(c)}"
    "function clr(){$('out').textContent=''}"
    "poll();setInterval(poll,2000);"
    "document.addEventListener('keydown',e=>{if(e.key==='Enter'&&"
    "document.activeElement===$('cmd'))run()});"
    "</script></body></html>";

static std::string UrlDecode(const std::string& s) {
  std::string o;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '%' && i + 2 < s.size()) {
      char h[3] = {s[i + 1], s[i + 2], 0};
      o += (char)strtol(h, nullptr, 16);
      i += 2;
    } else if (s[i] == '+') {
      o += ' ';
    } else {
      o += s[i];
    }
  }
  return o;
}

static void HttpSend(SOCKET c, const char* ctype, const std::string& body) {
  char hdr[256];
  int hl = _snprintf_s(hdr, _TRUNCATE,
                       "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
                       "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                       ctype, body.size());
  send(c, hdr, hl, 0);
  size_t off = 0;
  while (off < body.size()) {
    int w = send(c, body.data() + off, (int)(body.size() - off), 0);
    if (w <= 0) break;
    off += (size_t)w;
  }
}

static DWORD WINAPI HttpServer(LPVOID) {
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
  int port = 18700 + (int)(GetCurrentProcessId() % 256);
  SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ls == INVALID_SOCKET) return 2;
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons((u_short)port);
  inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  if (bind(ls, (sockaddr*)&a, sizeof(a)) != 0 || listen(ls, 4) != 0) {
    tlog("tether: web ui bind failed (port %d in use?)", port);
    return 3;
  }
  tlog("tether: web ui at http://127.0.0.1:%d", port);
  for (;;) {
    SOCKET c = accept(ls, nullptr, nullptr);
    if (c == INVALID_SOCKET) continue;
    char req[4096] = {};
    int rl = 0, r;
    while (rl < (int)sizeof(req) - 1 &&
           (r = recv(c, req + rl, (int)sizeof(req) - 1 - rl, 0)) > 0) {
      rl += r;
      if (strstr(req, "\r\n\r\n")) break;
    }
    char method[8] = {}, path[2048] = {};
    if (sscanf(req, "%7s %2047s", method, path) == 2 &&
        !strcmp(method, "GET")) {
      if (!strncmp(path, "/api/exec?c=", 12)) {
        std::string cmd = UrlDecode(path + 12);
        std::string resp = HandleCommand(cmd.c_str());
        if (resp.empty()) resp = "ERR empty\n.";
        HttpSend(c, "text/plain; charset=utf-8", resp);
      } else if (!strcmp(path, "/")) {
        HttpSend(c, "text/html; charset=utf-8", kDashboard);
      } else {
        HttpSend(c, "text/plain", "404\n.");
      }
    }
    closesocket(c);
  }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(h);
    SyrInit();
    tlog("tether: attached pid=%lu", GetCurrentProcessId());
    g_thread = CreateThread(nullptr, 0, PipeServer, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, HttpServer, nullptr, 0, nullptr);
  } else if (reason == DLL_PROCESS_DETACH) {
    if (g_frozen) ForEachOtherThread(false);
  }
  return TRUE;
}
