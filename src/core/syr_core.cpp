// syr_core.cpp —— MinHook 之上的薄封装: .syhk64 登记段扫描 + 安装/卸载 +
// RWX 写原语 + 特征码扫描 + 牵引 API 表。不包含任何自研指令重定位代码——
// 偷指令与跳板全部由 MinHook (vendor/minhook, BSD-2) 完成。
#include <windows.h>
#include <psapi.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <vector>

#include "MinHook.h"
#include "syringe.hpp"

namespace syr {
namespace detail {

struct Installed {
  uintptr_t target;
  char name[64];
};

static std::vector<Installed> g_hooks;
static bool g_init = false;
static CRITICAL_SECTION g_lock;

// 简单追加式日志: 引擎侧任何输出都进这里(牵引/自测可取走)。
static char g_log[16384];
static size_t g_log_len;

void log_line(const char* s) {
  static LONG once = 0;
  if (!InterlockedExchange(&once, 1)) InitializeCriticalSection(&g_lock);
  EnterCriticalSection(&g_lock);
  size_t n = strlen(s);
  if (g_log_len + n + 2 < sizeof(g_log)) {
    memcpy(g_log + g_log_len, s, n);
    g_log[g_log_len + n] = '\n';
    g_log_len += n + 1;
    g_log[g_log_len] = 0;
  }
  LeaveCriticalSection(&g_lock);
}

}  // namespace detail
}  // namespace syr

using namespace syr;

static void logf(const char* fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
  va_end(ap);
  detail::log_line(buf);
}

static const char* mh_name(MH_STATUS s) {
  switch (s) {
    case MH_OK: return "OK";
    case MH_ERROR_ALREADY_INITIALIZED: return "ALREADY_INIT";
    case MH_ERROR_NOT_INITIALIZED: return "NOT_INIT";
    case MH_ERROR_ALREADY_CREATED: return "ALREADY";
    case MH_ERROR_NOT_CREATED: return "NOT_CREATED";
    case MH_ERROR_ENABLED: return "ENABLED";
    case MH_ERROR_DISABLED: return "DISABLED";
    case MH_ERROR_NOT_EXECUTABLE: return "NOT_EXECUTABLE";
    case MH_ERROR_UNSUPPORTED_FUNCTION: return "UNSUPPORTED";
    case MH_ERROR_MEMORY_ALLOC: return "ALLOC_FAILED";
    case MH_ERROR_MEMORY_PROTECT: return "PROTECT_FAILED";
    case MH_ERROR_MODULE_NOT_FOUND: return "MODULE_NOT_FOUND";
    case MH_ERROR_FUNCTION_NOT_FOUND: return "FUNC_NOT_FOUND";
    default: return "MH_ERROR";
  }
}

// ---- 引擎 C API -------------------------------------------------------------
extern "C" {

__declspec(dllexport) int SyrInit(void) {
  if (detail::g_init) return 0;
  MH_STATUS s = MH_Initialize();
  if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
    logf("syr: MH_Initialize failed %d", (int)s);
    return -1;
  }
  detail::g_init = true;
  logf("syr: core ready (ver %d, engine=MinHook)", SYR_VERSION);
  return 0;
}

__declspec(dllexport) uintptr_t SyrModuleBase(const wchar_t* module) {
  HMODULE h = module ? GetModuleHandleW(module) : GetModuleHandleW(nullptr);
  return (uintptr_t)h;
}

__declspec(dllexport) int SyrHookRegister(uintptr_t target, void* detour,
                                          void** original, const char* name) {
  if (!detail::g_init) SyrInit();
  if (!detail::g_init) return -1;
  for (auto& k : detail::g_hooks)
    if (k.target == target) {
      logf("hook addr=%016llX name=%s ALREADY", (unsigned long long)target, name ? name : "?");
      return 2;
    }
  MH_STATUS s = MH_CreateHook((void*)target, detour, original);
  if (s != MH_OK) {
    logf("hook addr=%016llX name=%s %s", (unsigned long long)target,
         name ? name : "?", mh_name(s));
    return 4;
  }
  s = MH_EnableHook((void*)target);
  if (s != MH_OK) {
    MH_RemoveHook((void*)target);
    logf("hook addr=%016llX name=%s enable=%s", (unsigned long long)target,
         name ? name : "?", mh_name(s));
    return 5;
  }
  detail::Installed inst{};
  inst.target = target;
  _snprintf_s(inst.name, _TRUNCATE, "%s", name ? name : "?");
  detail::g_hooks.push_back(inst);
  logf("hook addr=%016llX name=%s OK tramp=%p", (unsigned long long)target,
       inst.name, original ? *original : nullptr);
  return 0;
}

__declspec(dllexport) int SyrHookRemove(uintptr_t target) {
  for (auto it = detail::g_hooks.begin(); it != detail::g_hooks.end(); ++it) {
    if (it->target == target) {
      MH_DisableHook((void*)target);
      MH_RemoveHook((void*)target);
      logf("unhook addr=%016llX name=%s OK", (unsigned long long)target, it->name);
      detail::g_hooks.erase(it);
      return 0;
    }
  }
  return 1;
}

__declspec(dllexport) int SyrWriteMem(uintptr_t addr, const void* buf, size_t len) {
  DWORD oldp = 0;
  if (!VirtualProtect((void*)addr, len, PAGE_EXECUTE_READWRITE, &oldp)) return 1;
  memcpy((void*)addr, buf, len);
  VirtualProtect((void*)addr, len, oldp, &oldp);
  FlushInstructionCache(GetCurrentProcess(), (void*)addr, len);
  return 0;
}

// SEH 安全读: 不可读返回 1, 不让 payload 因野指针崩溃。
static bool SyrSafeRead(uintptr_t addr, void* buf, size_t len) {
  __try { memcpy(buf, (const void*)addr, len); return true; }
  __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

__declspec(dllexport) int SyrReadMem(uintptr_t addr, void* buf, size_t len) {
  return SyrSafeRead(addr, buf, len) ? 0 : 1;
}

__declspec(dllexport) uintptr_t SyrAllocMem(size_t size, int exec) {
  DWORD prot = exec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
  return (uintptr_t)VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, prot);
}

__declspec(dllexport) void SyrFreeMem(uintptr_t addr) {
  if (addr) VirtualFree((void*)addr, 0, MEM_RELEASE);
}

__declspec(dllexport) uint32_t SyrProtect(uintptr_t addr, size_t len, uint32_t new_prot) {
  DWORD oldp = 0;
  if (!VirtualProtect((void*)addr, len, new_prot, &oldp)) return 0;
  if (new_prot & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ |
                  PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE))
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, len);
  return oldp;
}

// pattern: "48 8B 05 ?? ??"; ?? / * 为通配字节。
__declspec(dllexport) int SyrScanPattern(const wchar_t* module, const char* pattern,
                                         uintptr_t* out, int max_out) {
  if (!detail::g_init) SyrInit();
  uintptr_t base = SyrModuleBase(module);
  if (!base) return -1;
  auto* dos = (IMAGE_DOS_HEADER*)base;
  auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
  size_t img = nt->OptionalHeader.SizeOfImage;

  std::vector<std::pair<uint8_t, bool>> pat;  // (byte, wildcard)
  const char* p = pattern;
  while (*p) {
    if ((p[0] == '?' && p[1] == '?') || (p[0] == '*' && p[1] == '*')) {
      pat.push_back({0, true});
      p += 2;
    } else if (p[0] == '?') {
      pat.push_back({0, true});
      p += 1;
    } else {
      char* end = nullptr;
      unsigned long b = strtoul(p, &end, 16);
      if (end == p) { p++; continue; }
      pat.push_back({(uint8_t)b, false});
      p = end;
    }
    while (*p == ' ' || *p == '\t') p++;
  }
  if (pat.empty() || pat.size() > img) return -2;

  int found = 0;
  const uint8_t* hay = (const uint8_t*)base;
  for (size_t i = 0; i + pat.size() <= img && found < max_out; i++) {
    size_t j = 0;
    for (; j < pat.size(); j++)
      if (!pat[j].second && hay[i + j] != pat[j].first) break;
    if (j == pat.size()) out[found++] = base + i;
  }
  return found;
}

__declspec(dllexport) int SyrInstallSection(void* module) {
  if (!detail::g_init) SyrInit();
  auto* dos = (IMAGE_DOS_HEADER*)module;
  if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
  auto* nt = (IMAGE_NT_HEADERS*)((uintptr_t)module + dos->e_lfanew);
  auto* sec = IMAGE_FIRST_SECTION(nt);
  int installed = 0;
  for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (strcmp((char*)sec[i].Name, ".syhk64") != 0) continue;
    uintptr_t va = (uintptr_t)module + sec[i].VirtualAddress;
    size_t raw = sec[i].SizeOfRawData;
    for (size_t off = 0; off + sizeof(detail::HookDecl) <= raw; off += sizeof(detail::HookDecl)) {
      auto* d = (detail::HookDecl*)(va + off);
      if (d->magic != detail::kMagic) break;
      if (!d->detour || !d->target) continue;
      uintptr_t target = d->module ? SyrModuleBase(d->module) + (uintptr_t)d->target
                                   : (uintptr_t)d->target;
      if (!target) { logf("hook name=%s MODULE_NOT_FOUND", d->name); continue; }
      if (SyrHookRegister(target, d->detour, d->original, d->name) == 0) installed++;
    }
  }
  logf("section: %d hook(s) installed for module %p", installed, module);
  return installed;
}

__declspec(dllexport) const char* SyrGetLog(void) { return detail::g_log; }

__declspec(dllexport) int SyrHookCount(void) { return (int)detail::g_hooks.size(); }

static char g_hooks_info[4096];
__declspec(dllexport) const char* SyrHooksInfo(void) {
  char* p = g_hooks_info;
  char* end = g_hooks_info + sizeof(g_hooks_info) - 1;
  for (auto& k : detail::g_hooks) {
    int w = _snprintf(p, (size_t)(end - p), "%016llX %s\n",
                      (unsigned long long)k.target, k.name);
    if (w < 0 || p + w >= end) break;
    p += w;
  }
  *p = 0;
  return g_hooks_info;
}

__declspec(dllexport) void* SyrLastThunk(void) { return nullptr; }  // 兼容占位

}  // extern "C"

// ---- 牵引用的 API 表(注入给 payload) ----------------------------------------
static void syr_api_log(const char* fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
  va_end(ap);
  logf("%s", buf);
}

static Api g_api_table = {
    SYR_VERSION,
    SyrModuleBase,
    SyrHookRegister,
    SyrHookRemove,
    SyrWriteMem,
    SyrScanPattern,
    SyrInstallSection,
    syr_api_log,
    SyrReadMem,
    SyrAllocMem,
    SyrFreeMem,
    SyrProtect,
};

extern "C" __declspec(dllexport) const Api* SyrGetApi(void) { return &g_api_table; }
