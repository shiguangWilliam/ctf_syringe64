// payload_wce_test.cpp —— 真实游戏(Mono 后端)闭环验证 payload。
// 链路: mono 解析表(进程内 GetProcAddress) -> 定位 GameUtility::GetNetworkTypeByCode
//       -> mono_compile_method 物化 JIT 地址 -> MinHook 钩取 -> mono_runtime_invoke
//       主动触发一次 -> detour 命中写日志。全程不改游戏行为(纯函数, 调完即弃)。
#include "syringe.hpp"

namespace syr { Api* g_api = nullptr; }  // 本 payload 自带入口, 手动提供存储

// ---- mono 运行时(全部动态解析, 引擎不感知 mono) ----
static void* (*mono_get_root_domain)();
static void* (*mono_thread_attach)(void*);
static void* (*mono_image_loaded)(const char*);
static void* (*mono_class_from_name)(void*, const char*, const char*);
static void* (*mono_class_get_method_from_name)(void*, const char*, int);
static void* (*mono_compile_method)(void*);
static void* (*mono_string_new)(void*, const char*);
static void* (*mono_runtime_invoke)(void*, void*, void**, void**);

static bool LoadMonoTable(void) {
  HMODULE m = GetModuleHandleW(L"mono-2.0-bdwgc.dll");
  if (!m) return false;
#define RES(slot, name) \
  slot = (decltype(slot))(void*)GetProcAddress(m, name); \
  if (!slot) return false;
  RES(mono_get_root_domain, "mono_get_root_domain")
  RES(mono_thread_attach, "mono_thread_attach")
  RES(mono_image_loaded, "mono_image_loaded")
  RES(mono_class_from_name, "mono_class_from_name")
  RES(mono_class_get_method_from_name, "mono_class_get_method_from_name")
  RES(mono_compile_method, "mono_compile_method")
  RES(mono_string_new, "mono_string_new")
  RES(mono_runtime_invoke, "mono_runtime_invoke")
#undef RES
  return true;
}

static int g_hits = 0;
// 静态方法签名: (MonoString* code) -> enum(int)。detour 只观察不改。
static void D_GetNetworkTypeByCode(void* code, void*) {
  g_hits++;
  if (g_hits <= 3) syr::g_api->log("WCE: HIT GetNetworkTypeByCode code_str=%p", code);
}

static int WceInit(const syr::Api* api);

// 自举: 该游戏(WCE)拒绝进程内 LdrLoadDll, payload 需由 launcher 外部装载;
// 装载后从常驻牵引拿 Api 表自己完成初始化。
static DWORD WINAPI Bootstrap(LPVOID) {
  Sleep(200);  // 等装载稳定, 避开 loader lock
  HMODULE t = GetModuleHandleW(L"syringe-tether.dll");
  if (!t) return 1;
  auto getapi = (const syr::Api * (__cdecl*)(void))GetProcAddress(t, "SyrGetApi");
  if (!getapi) return 2;
  return WceInit(getapi()) == 1 ? 0 : 3;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(h);
    CreateThread(nullptr, 0, Bootstrap, nullptr, 0, nullptr);
  }
  return TRUE;
}

static int WceInit(const syr::Api* api) {
  if (!api || api->version < SYR_API_MIN) return -100;
  syr::g_api = const_cast<syr::Api*>(api);
  api->log("WCE: payload init");

  if (!LoadMonoTable()) { api->log("WCE: mono table load FAILED"); return -1; }
  api->log("WCE: mono table OK");

  void* dom = mono_get_root_domain();
  mono_thread_attach(dom);
  api->log("WCE: thread attached, domain=%p", dom);

  void* img = mono_image_loaded("Assembly-CSharp");
  api->log("WCE: image Assembly-CSharp = %p", img);
  if (!img) return -2;

  void* k = mono_class_from_name(img, "", "GameUtility");
  api->log("WCE: class GameUtility = %p", k);
  if (!k) return -3;

  void* m = mono_class_get_method_from_name(k, "GetNetworkTypeByCode", 1);
  if (!m) {
    // 兜底: 迭代全部方法按名找(参数个数可能对不上)
    static void* (*mono_class_get_methods)(void*, void**);
    static const char* (*mono_method_get_name)(void*);
    HMODULE mo = GetModuleHandleW(L"mono-2.0-bdwgc.dll");
    mono_class_get_methods = (decltype(mono_class_get_methods))(void*)GetProcAddress(mo, "mono_class_get_methods");
    mono_method_get_name = (decltype(mono_method_get_name))(void*)GetProcAddress(mo, "mono_method_get_name");
    if (mono_class_get_methods && mono_method_get_name) {
      void* iter = nullptr;
      void* mm;
      int nmethods = 0;
      while ((mm = mono_class_get_methods(k, &iter)) != nullptr) {
        nmethods++;
        const char* nm = mono_method_get_name(mm);
        if (nm && !strcmp(nm, "GetNetworkTypeByCode")) { m = mm; break; }
      }
      api->log("WCE: iterated %d methods, fallback match = %p", nmethods, m);
    }
  }
  api->log("WCE: method GetNetworkTypeByCode = %p", m);
  if (!m) return -4;

  uintptr_t addr = (uintptr_t)mono_compile_method(m);
  api->log("WCE: jit addr = %016llx", (unsigned long long)addr);
  if (!addr) return -5;

  if (api->hook_register(addr, (void*)&D_GetNetworkTypeByCode, nullptr,
                         "GameUtility::GetNetworkTypeByCode") != 0) {
    api->log("WCE: hook_register FAILED");
    return -6;
  }
  api->log("WCE: hook installed on jit code");

  // 主动触发: 构造参数并 invoke(静态纯函数, 无副作用)
  void* s = mono_string_new(dom, "LC_TEST");
  void* args[1] = {s};
  void* res = mono_runtime_invoke(m, nullptr, args, nullptr);
  // MonoObject*: vtable/sync 头之后是数据域; enum 返回值按 int 取
  int val = res ? *(int*)((uintptr_t)res + 8) : -1;
  api->log("WCE: invoke result obj=%p enum=%d (Local=1?) hits=%d", res, val, g_hits);

  api->log("WCE: %s", g_hits > 0 ? "FULL LOOP PASS (resolve->jit->hook->invoke->hit)"
                                 : "invoke done but no hit (check signature)");
  return g_hits > 0 ? 1 : 0;
}
