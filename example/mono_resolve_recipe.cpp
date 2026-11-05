// mono_resolve_recipe.cpp —— payload 侧配方示例(引擎不含 mono 概念)。
//
// 展示: payload 自己 GetProcAddress 解析 mono 运行时, 把 "类.方法" 物化成
// 运行时地址, 然后交给引擎的 hook_register。注入器自始至终不感知 mono。
// 本文件为文档性质配方: 目标机无 mono 时编译照常通过(全部动态解析)。
#include "syringe.hpp"

// ---- mono 运行时函数指针(全部运行期解析) ----
static void* (*mono_get_root_domain)();
static void* (*mono_thread_attach)(void* domain);
static void* (*mono_image_loaded)(const char* name);
static void* (*mono_class_from_name)(void* image, const char* ns, const char* name);
static void* (*mono_class_get_method_from_name)(void* klass, const char* name, int argc);
static void* (*mono_compile_method)(void* method);

static bool LoadMonoTable(void) {
  HMODULE m = GetModuleHandleW(L"mono-2.0-bdwgc.dll");
  if (!m) m = GetModuleHandleW(L"EmbedMessenger_wsa.dll");  // 部分发行改名
  if (!m) return false;
#define RES(slot, name) \
  slot = (decltype(slot))(void*)GetProcAddress(m, name);     \
  if (!slot) return false;
  RES(mono_get_root_domain, "mono_get_root_domain")
  RES(mono_thread_attach, "mono_thread_attach")
  RES(mono_image_loaded, "mono_image_loaded")
  RES(mono_class_from_name, "mono_class_from_name")
  RES(mono_class_get_method_from_name, "mono_class_get_method_from_name")
  RES(mono_compile_method, "mono_compile_method")
#undef RES
  return true;
}

// 名字 -> 运行时机器码地址(JIT 产物在堆上 RWX, 离线拿不到, 此处物化)
static uintptr_t MonoResolve(const char* image, const char* ns,
                             const char* cls, const char* method, int argc) {
  if (!LoadMonoTable()) return 0;
  mono_thread_attach(mono_get_root_domain());  // GC 安全
  void* img = mono_image_loaded(image);
  if (!img) return 0;
  void* k = mono_class_from_name(img, ns, cls);
  if (!k) return 0;
  void* m = mono_class_get_method_from_name(k, method, argc);
  if (!m) return 0;
  return (uintptr_t)mono_compile_method(m);  // 强制 JIT, 返回稳定入口
}

// ---- 用法: 与引擎完全是普通一期接口 ----
//
// static void (*OrigDie)(void* self);
// static void D_Die(void* self) { /* 跳过 */ }
//
// extern "C" __declspec(dllexport) int __cdecl
// SyrPayloadInit(const syr::Api* api) {
//   uintptr_t die = MonoResolve("Assembly-CSharp", "Game", "Player", "Die", 1);
//   if (!die) return -1;
//   syr::g_api = const_cast<syr::Api*>(api);
//   return api->hook_register(die, (void*)&D_Die, (void**)&OrigDie, "Player::Die");
// }
//
// 定位不到名字时: 分析侧给特征码, 用 api->scan_rwx("48 8B ...") 直接找堆上代码。
