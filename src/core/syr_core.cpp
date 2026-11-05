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

// 跨全进程扫描可执行页(堆上 RWX/私有 RX): 定位 JIT 产物/运行期生成代码的
// 通用手段, 不耦合任何运行时(与 mono/IL 解析无关)。
static int ParsePattern(const char* pattern, std::vector<std::pair<uint8_t, bool>>& pat) {
  const char* p = pattern;
  while (*p) {
    if ((p[0] == '?' && p[1] == '?') || (p[0] == '*' && p[1] == '*')) {
      pat.push_back({0, true}); p += 2;
    } else if (p[0] == '?') {
      pat.push_back({0, true}); p += 1;
    } else {
      char* end = nullptr;
      unsigned long b = strtoul(p, &end, 16);
      if (end == p) { p++; continue; }
      pat.push_back({(uint8_t)b, false});
      p = end;
    }
    while (*p == ' ' || *p == '\t') p++;
  }
  return pat.empty() ? -2 : 0;
}

// 无 C++ 对象的 SEH 扫描体(__try 不能与对象展开共存)
static int ScanRegionFor(const uint8_t* hay, size_t rsz,
                         const std::pair<uint8_t, bool>* pat, size_t patn,
                         uintptr_t* out, int max_out, int start_idx) {
  int found = start_idx;
  __try {
    for (size_t i = 0; i + patn <= rsz && found < max_out; i++) {
      size_t j = 0;
      for (; j < patn; j++)
        if (!pat[j].second && hay[i + j] != pat[j].first) break;
      if (j == patn) out[found++] = (uintptr_t)(hay + i);
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) { /* 换页竞态: 跳过本区 */ }
  return found;
}

__declspec(dllexport) int SyrScanRwx(const char* pattern, uintptr_t* out, int max_out) {
  if (!detail::g_init) SyrInit();
  std::vector<std::pair<uint8_t, bool>> pat;
  if (ParsePattern(pattern, pat) != 0) return -2;

  int found = 0;
  SYSTEM_INFO si{};
  GetSystemInfo(&si);
  uintptr_t cur = (uintptr_t)si.lpMinimumApplicationAddress;
  MEMORY_BASIC_INFORMATION mbi{};
  while (cur < (uintptr_t)si.lpMaximumApplicationAddress && found < max_out) {
    if (VirtualQuery((void*)cur, &mbi, sizeof(mbi)) == 0) break;
    bool exec = (mbi.State == MEM_COMMIT) &&
                (mbi.Type == MEM_PRIVATE) &&  // JIT 堆/MinHook 跳板都是 private
                (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE));
    if (exec && mbi.RegionSize >= pat.size()) {
      found = ScanRegionFor((const uint8_t*)mbi.BaseAddress, mbi.RegionSize,
                            pat.data(), pat.size(), out, max_out, found);
    }
    cur = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
  }
  return found;
}

// ---- CFG: 状态查询 + 任意执行地址的位图放行(通用能力, 与托管运行时无关) ----
__declspec(dllexport) int SyrCfgBitmapSet(uintptr_t addr);  // 前向声明(实现在位图直写节)
static uint32_t MainModuleGuardFlags(void) {
  IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)GetModuleHandleW(nullptr);
  if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
  IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uintptr_t)dos + dos->e_lfanew);
  DWORD lcdir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
  if (!lcdir) return 0;
  IMAGE_LOAD_CONFIG_DIRECTORY* cfg =
      (IMAGE_LOAD_CONFIG_DIRECTORY*)((uintptr_t)dos + lcdir);
  if (cfg->Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags) + sizeof(uint32_t))
    return 0;
  return cfg->GuardFlags;
}

__declspec(dllexport) int SyrCfgStatus(void) {
  uint32_t f = MainModuleGuardFlags();
  return (f & IMAGE_GUARD_CF_INSTRUMENTED) ? 1 : 0;
}

__declspec(dllexport) int SyrCfgValidate(uintptr_t addr, size_t len) {
  if (!SyrCfgStatus()) return 0;   // 未开 CFG: 恒通过
  // 官方 API 逐模块解析(新系统仅 kernelbase 导出, 老系统在 kernel32)。
  using Fn = BOOL(WINAPI*)(HANDLE, PVOID, ULONG, PVOID, PULONG);
  static Fn fn = nullptr;
  static bool tried = false;
  if (!tried) {
    tried = true;
    for (auto m : {L"kernel32.dll", L"kernelbase.dll", L"ntdll.dll"}) {
      fn = (Fn)(void*)GetProcAddress(GetModuleHandleW(m), "SetProcessValidCallTargets");
      if (fn) break;
    }
  }
  if (!fn) {  // API 不在(部分新系统): 退位图直写; 位图也定位不到则记日志放行
    int br = SyrCfgBitmapSet(addr);
    if (br == 2) logf("cfg_validate %016llX: user bitmap absent (kernel-CFG host), "
                      "pass-through", (unsigned long long)addr);
    return br == 3 ? 3 : 0;
  }
  struct { ULONG Offset; ULONG Flags; } info{};  // CFG_CALL_TARGET_INFO 等价
  info.Offset = (ULONG)(addr & 0xFFFFFFFF);
  info.Flags = 1 /* CFG_CALL_TARGET_VALID */;
  ULONG processed = 0;
  if (!fn(GetCurrentProcess(), nullptr, 1, &info, &processed)) {
    // API 拒收(如内核化 CFG 的系统): 位图兜底; 仍不行则记日志放行。
    int br = SyrCfgBitmapSet(addr);
    logf("cfg_validate %016llX: API refused gle=%lu, bitmap=%d",
         (unsigned long long)addr, GetLastError(), br);
    return br == 3 ? 3 : 0;
  }
  (void)len;
  return 0;
}

// ---- PE 视角服务: 段表 / 导出自解析 / 区间扫描(零耦合, 只读 PE 结构) --------
static bool SyrSafeReadBlock(uintptr_t addr, void* buf, size_t len) {
  __try { memcpy(buf, (const void*)addr, len); return true; }
  __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static IMAGE_NT_HEADERS64* PeNt(uintptr_t base) {
  IMAGE_DOS_HEADER dos{};
  if (!SyrSafeReadBlock(base, &dos, sizeof(dos))) return nullptr;
  if (dos.e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
  auto* nt = (IMAGE_NT_HEADERS64*)(base + dos.e_lfanew);
  uint32_t sig = 0;
  if (!SyrSafeReadBlock((uintptr_t)nt, &sig, sizeof(sig))) return nullptr;
  if (sig != IMAGE_NT_SIGNATURE) return nullptr;
  return nt;
}

__declspec(dllexport) int SyrPeSections(uintptr_t base, syr::SectionInfo* out, int max_out) {
  auto* nt = PeNt(base);
  if (!nt || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return -1;
  auto* sec = IMAGE_FIRST_SECTION(nt);
  int n = nt->FileHeader.NumberOfSections;
  if (n > max_out) n = max_out;
  for (int i = 0; i < n; i++) {
    memcpy(out[i].name, sec[i].Name, 8);
    out[i].name[7] = 0;  // 段名非零结尾时截断保安全
    for (int k = 0; k < 8; k++) if (out[i].name[k] == 0) break;
    out[i].va = base + sec[i].VirtualAddress;
    out[i].vsize = sec[i].Misc.VirtualSize;
    out[i].exec = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 1 : 0;
    out[i].flags = sec[i].Characteristics;
  }
  return n;
}

static int ScanRangeSeh(const uint8_t* hay, size_t rsz,
                        const std::pair<uint8_t, bool>* pat, size_t patn,
                        uintptr_t* out, int max_out) {
  int found = 0;
  __try {
    for (size_t i = 0; i + patn <= rsz && found < max_out; i++) {
      size_t j = 0;
      for (; j < patn; j++)
        if (!pat[j].second && hay[i + j] != pat[j].first) break;
      if (j == patn) out[found++] = (uintptr_t)(hay + i);
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
  return found;
}

__declspec(dllexport) int SyrScanRange(uintptr_t start, uintptr_t end,
                                       const char* pattern, uintptr_t* out, int max_out) {
  if (!detail::g_init) SyrInit();
  if (end <= start) return -2;
  std::vector<std::pair<uint8_t, bool>> pat;
  if (ParsePattern(pattern, pat) != 0) return -2;
  return ScanRangeSeh((const uint8_t*)start, (size_t)(end - start),
                      pat.data(), pat.size(), out, max_out);
}

__declspec(dllexport) uintptr_t SyrPeExport(uintptr_t base, const char* name) {
  auto* nt = PeNt(base);
  if (!nt) return 0;
  DWORD dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  DWORD dirs = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  if (!dir || !dirs) return 0;
  auto* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir);
  IMAGE_EXPORT_DIRECTORY e{};
  if (!SyrSafeReadBlock((uintptr_t)exp, &e, sizeof(e))) return 0;
  uint32_t nnames = e.NumberOfNames;
  if (!nnames || !e.AddressOfNames || !e.AddressOfFunctions ||
      !e.AddressOfNameOrdinals)
    return 0;
  auto* names = (const uint32_t*)(base + e.AddressOfNames);
  auto* ords = (const uint16_t*)(base + e.AddressOfNameOrdinals);
  auto* funcs = (const uint32_t*)(base + e.AddressOfFunctions);
  for (DWORD i = 0; i < nnames; i++) {
    uint32_t nrva = 0;
    uint16_t o = 0;
    if (!SyrSafeReadBlock((uintptr_t)(names + i), &nrva, 4)) break;
    if (!SyrSafeReadBlock((uintptr_t)(ords + i), &o, 2)) break;
    const char* fname = (const char*)(base + nrva);
    bool eq = true;
    for (int k = 0; k < 256; k++) {
      char a = 0, b = name[k];
      if (!SyrSafeReadBlock((uintptr_t)(fname + k), &a, 1)) { eq = false; break; }
      if (a != b) { eq = false; break; }
      if (a == 0) break;  // 同时为零 => 相等
    }
    if (!eq) continue;
    uint32_t frva = 0;
    if (!SyrSafeReadBlock((uintptr_t)(funcs + o), &frva, 4)) return 0;
    // 转发导出: frva 落在 export 目录内 => 指向别处, 不解引用, 返回原 VA 供判断
    return base + frva;
  }
  return 0;
}

// ---- CFG bitmap 直写: 在 ntdll 数据段里找指向位图区的索引指针 ----
// 原理: CFG 位图(1bit=8字节, 稀疏压缩白名单)的基址一定被 ntdll 某数据槽索引。
// 指纹: 页对齐指针 + 指向巨型保留区 + "已知合法间接调用目标(kernel32 导出函数)
// 对应位已置 1"。篡改位图不影响地址空间布局(只在既有位图内改位)。
static uintptr_t g_cfg_bitmap = 0;

static bool LooksLikeCfgBitmap(uintptr_t bm) {
  if (bm < 0x10000 || bm > 0x7FFFFFFFFFFFull || (bm & 0xFFF)) return false;
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  if (!k32) return false;
  uintptr_t known = (uintptr_t)GetProcAddress(k32, "GetProcAddress");
  if (!known) return false;
  MEMORY_BASIC_INFORMATION mbi{};
  if (!VirtualQuery((void*)bm, &mbi, sizeof(mbi))) return false;
  if (mbi.RegionSize < 0x800000000ull) return false;  // >=512GB 巨型区
  uint8_t byte = 0;
  if (!SyrSafeReadBlock(bm + (known >> 9), &byte, 1)) return false;
  return (byte >> ((known >> 3) & 63)) & 1;
}

static uintptr_t FindCfgBitmapBase(void) {
  if (g_cfg_bitmap) return g_cfg_bitmap;
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  if (!nt) return 0;
  IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)nt;
  IMAGE_NT_HEADERS* nth = (IMAGE_NT_HEADERS*)((uintptr_t)nt + dos->e_lfanew);
  auto* sec = IMAGE_FIRST_SECTION(nth);
  for (int i = 0; i < nth->FileHeader.NumberOfSections && !g_cfg_bitmap; i++) {
    if (!(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
    if (!(sec[i].Characteristics & IMAGE_SCN_MEM_READ)) continue;
    uintptr_t base = (uintptr_t)nt + sec[i].VirtualAddress;
    size_t sz = sec[i].Misc.VirtualSize;
    for (size_t k = 0; k + 8 <= sz; k += 8) {
      uintptr_t p = 0;
      if (!SyrSafeReadBlock(base + k, &p, 8)) break;
      if (LooksLikeCfgBitmap(p)) {
        g_cfg_bitmap = p;
        logf("cfg: bitmap base = %016llX (ntdll data index sec=%d off=%zx)",
             (unsigned long long)p, i, k);
        break;
      }
    }
  }
  if (!g_cfg_bitmap) logf("cfg: bitmap index pointer not found");
  return g_cfg_bitmap;
}

// 把 addr 加入 CFG 白名单位图。返回 0 成功; 1=未开CFG(无需处理); 2=定位失败; 3=写失败
__declspec(dllexport) int SyrCfgBitmapSet(uintptr_t addr) {
  if (!SyrCfgStatus()) return 1;
  uintptr_t base = FindCfgBitmapBase();
  if (!base) return 2;
  uintptr_t byte_at = base + (addr >> 9);
  uint8_t old = 0;
  if (!SyrSafeReadBlock(byte_at, &old, 1)) return 3;
  uint8_t nv = old | (uint8_t)(1u << ((addr >> 3) & 63));
  if (nv != old) {
    if (SyrWriteMem(byte_at, &nv, 1) != 0) return 3;
    uint8_t chk = 0;
    if (!SyrSafeReadBlock(byte_at, &chk, 1) || chk != nv) return 3;
  }
  return 0;
}

__declspec(dllexport) uintptr_t SyrCfgBitmapBase(void) {
  return SyrCfgStatus() ? FindCfgBitmapBase() : 0;
}

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
    SyrScanRwx,
    SyrCfgStatus,
    SyrCfgValidate,
    SyrPeSections,
    SyrPeExport,
    SyrScanRange,
    SyrCfgBitmapSet,
    SyrCfgBitmapBase,
};

extern "C" __declspec(dllexport) const Api* SyrGetApi(void) { return &g_api_table; }
