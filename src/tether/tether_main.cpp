// tether_main.cpp —— 牵引 DLL: 命名管道控制面 + payload 追加 + 冻结/解冻。
//
// 管道名 \\.\pipe\syringe64-<pid>, 行协议(ASCII/UTF-8, 单行命令, 多行应答以单独的 "." 行结束):
//   hello
//   modules
//   read <hexaddr> <len>
//   write <hexaddr> <hexbytes>          自动走 RWX 写原语
//   scan <modulename|*> "<pattern>"     例: scan * "48 89 5C 24 ?? 57"
//   scanrwx "<pattern>"                 全进程私有可执行页扫描(定位 JIT 产物)
//   load <绝对路径.dll>                  LoadLibraryExW + 调 SyrPayloadInit
//   hooks
//   log
//   freeze | thaw                       冻结/恢复其他全部线程(装钩子辅助)
//   alloc <len> [exec] | free <addr>   进程内分配(RWX/RW)与释放
//   quit                                关闭本连接(牵引常驻)
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <string>

#include "syringe.hpp"
#include "core_exports.hpp"

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

// SEH 安全读(__try 不能出现在带 C++ 对象展开的函数里)
static bool SafeRead(uintptr_t addr, void* dst, size_t len) {
  __try { memcpy(dst, (const void*)addr, len); return true; }
  __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---- 管道服务 ---------------------------------------------------------------
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
      // 按行读(逐字节, 简单可靠)
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

      std::string reply;
      char arg1[512] = "", arg2[512] = "", arg3[512] = "";
      char cmd[64] = "";
      sscanf(line, "%63s %511s %511s %511s", cmd, arg1, arg2, arg3);

      if (!strcmp(cmd, "hello")) {
        char buf[256];
        _snprintf_s(buf, _TRUNCATE, "syringe64 tether v%d pid=%lu bits=64\n.",
                    SYR_VERSION, GetCurrentProcessId());
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
        if (!addr || len <= 0 || len > 2048) { reply = "ERR args\n."; goto send; }
        unsigned char tmp[2048];
        if (!SafeRead(addr, tmp, (size_t)len)) { reply = "ERR access\n."; goto send; }
        char hex[4096 + 1];
        for (int i = 0; i < len; i++) _snprintf_s(hex + i * 2, 3, _TRUNCATE, "%02X", tmp[i]);
        reply = hex; reply += "\n.";
      } else if (!strcmp(cmd, "write")) {
        uintptr_t addr = _strtoui64(arg1, nullptr, 16);
        size_t slen = strlen(arg2);
        if (!addr || slen == 0 || slen % 2 || slen > 2048) { reply = "ERR args\n."; goto send; }
        unsigned char tmp[1024];
        for (size_t i = 0; i < slen / 2; i++) {
          unsigned v; sscanf(arg2 + i * 2, "%2x", &v); tmp[i] = (unsigned char)v;
        }
        reply = SyrWriteMem(addr, tmp, slen / 2) == 0 ? "OK\n." : "ERR write\n.";
      } else if (!strcmp(cmd, "scan")) {
        // pattern 允许含空格: 从行中第一个引号取到最后一个引号
        char patbuf[512] = "";
        const char* q1 = strchr(line, '"');
        if (q1) {
          const char* q2 = strrchr(q1 + 1, '"');
          size_t pl = q2 ? (size_t)(q2 - q1 - 1) : strlen(q1 + 1);
          if (pl >= sizeof(patbuf)) pl = sizeof(patbuf) - 1;
          memcpy(patbuf, q1 + 1, pl);
          patbuf[pl] = 0;
        }
        wchar_t mod[512] = L"";
        if (strcmp(arg1, "*") != 0)
          MultiByteToWideChar(CP_UTF8, 0, arg1, -1, mod, 512);
        if (!patbuf[0]) { reply = "ERR args\n."; goto send; }
        uintptr_t out[64];
        int nfound = SyrScanPattern(mod[0] ? mod : nullptr, patbuf, out, 64);
        if (nfound < 0) { reply = "ERR scan\n."; goto send; }
        char buf[64];
        for (int i = 0; i < nfound; i++) {
          _snprintf_s(buf, _TRUNCATE, "%016llx", (unsigned long long)out[i]);
          reply += buf; reply += "\n";
        }
        reply += ".";
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
      } else if (!strcmp(cmd, "scanrwx")) {
        // 跨全进程私有可执行页扫描: 定位 JIT 产物/运行期生成代码
        char patbuf[512] = "";
        const char* q1 = strchr(line, '"');
        if (q1) {
          const char* q2 = strrchr(q1 + 1, '"');
          size_t pl = q2 ? (size_t)(q2 - q1 - 1) : strlen(q1 + 1);
          if (pl >= sizeof(patbuf)) pl = sizeof(patbuf) - 1;
          memcpy(patbuf, q1 + 1, pl);
          patbuf[pl] = 0;
        }
        if (!patbuf[0]) { reply = "ERR args\n."; goto send; }
        uintptr_t out[64];
        int nfound = SyrScanRwx(patbuf, out, 64);
        if (nfound < 0) { reply = "ERR scan\n."; goto send; }
        char buf[64];
        for (int i = 0; i < nfound; i++) {
          _snprintf_s(buf, _TRUNCATE, "%016llx", (unsigned long long)out[i]);
          reply += buf; reply += "\n";
        }
        reply += ".";
      } else if (!strcmp(cmd, "alloc")) {
        size_t sz = (size_t)_strtoui64(arg1, nullptr, 0);
        int exec = atoi(arg2);
        uintptr_t a = SyrAllocMem(sz ? sz : 0x1000, exec);
        char buf[64];
        if (!a) _snprintf_s(buf, _TRUNCATE, "ERR alloc\n.");
        else _snprintf_s(buf, _TRUNCATE, "%016llx\n.", (unsigned long long)a);
        reply = buf;
      } else if (!strcmp(cmd, "free")) {
        uintptr_t a = _strtoui64(arg1, nullptr, 16);
        SyrFreeMem(a);
        reply = "OK\n.";
      } else if (!strcmp(cmd, "quit")) {
        reply = "BYE\n.";
        DWORD w = 0; WriteFile(pipe, reply.data(), (DWORD)reply.size(), &w, nullptr);
        FlushFileBuffers(pipe);
        break;
      } else if (!cmd[0]) {
        continue;
      } else {
        reply = "ERR unknown\n.";
      }
    send:
      if (!reply.empty()) {
        DWORD w = 0;
        WriteFile(pipe, reply.data(), (DWORD)reply.size(), &w, nullptr);
        FlushFileBuffers(pipe);
      }
      if (eof) break;
    }
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
  }
  return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(h);
    SyrInit();
    tlog("tether: attached pid=%lu", GetCurrentProcessId());
    g_thread = CreateThread(nullptr, 0, PipeServer, nullptr, 0, nullptr);
  } else if (reason == DLL_PROCESS_DETACH) {
    if (g_frozen) ForEachOtherThread(false);
  }
  return TRUE;
}
