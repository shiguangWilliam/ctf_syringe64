#pragma once
// ============================================================================
// ctf-syringe64 公共 API —— payload 作者唯一需要 include 的头。
//
// 引擎 = MinHook(指令重定位/跳板全自动) + 一层登记段与注入服务封装。
// 所有钩子都是 MinHook 式普通函数, 不需要任何汇编或特殊调用约定。
//
// 能力对照(与 ra3-preinject-syringe 对齐):
//   * reg(参数)篡改: detour 改形参后调 original; 返回值同样可控
//   * stack 参数篡改: detour 签名直接声明第 5+ 个参数(MSVC x64 自动走栈)
//   * 返回地址获取:  #include <intrin.h> 后 _ReturnAddress()
//   * 函数入口牵引:  SYR_HOOK(模块, RVA, Detour, &Original)
//   * 跳过逻辑:      detour 里不调 original, 直接 return 指定值
//   * 任意地址牵引:  ((RET(*)(ARGS...))addr)(args...) 替代 original 调用,
//                    栈帧由正常调用约定保证干净
//   * mem 篡改:      SYR_MEM_WRITE / g_api->write_mem(RWX 写原语)
//
// 编写一个钩子(完整范例见 example/payload_example.cpp):
//
//   static long long (*OrigAdd)(long long, long long);
//   long long MyAdd(long long a, long long b);     // 先声明
//   SYR_HOOK(L"GameAssembly.dll", 0x1234560, MyAdd, &OrigAdd)
//   long long MyAdd(long long a, long long b) {    // 再定义
//     return OrigAdd(a, b + 100);                  // 参数篡改后照常执行
//   }
//
//   ORIG 传 nullptr 表示不需要调用原函数(纯跳过型钩子)。
// ============================================================================

#include <cstddef>
#include <cstdint>
#if !defined(_WINDOWS_)
#include <windows.h>
#endif

#define SYR_VERSION 2

namespace syr {

// ---- 牵引DLL 注入给 payload 的 API 表 --------------------------------------
// payload 不链接引擎: 由 SYR_PAYLOAD() 生成的 SyrPayloadInit 收到这张函数指针表。
struct Api {
  int            version;
  // 目标模块基址(ASLR 下动态); module==nullptr 取主模块
  std::uintptr_t (*module_base)(const wchar_t* module);
  // 运行时登记钩子(MinHook CreateHook+EnableHook): target 为绝对地址
  int            (*hook_register)(std::uintptr_t target, void* detour,
                                  void** original, const char* name);
  int            (*hook_remove)(std::uintptr_t target);
  // RWX 写原语: 临时改保护->写->还原->刷指令缓存
  int            (*write_mem)(std::uintptr_t addr, const void* buf, std::size_t len);
  // 特征码扫描: pattern 形如 "48 8B 05 ?? ??", ?? 为通配
  int            (*scan)(const wchar_t* module, const char* pattern,
                         std::uintptr_t* out, int max_out);
  // 扫描指定模块的 .syhk64 登记段并全部安装(宏登记的钩子由此生效)
  int            (*install_section)(void* module);
  void           (*log)(const char* fmt, ...);
};

// payload 内全局 API 指针, SYR_PAYLOAD() 负责填充。
extern Api* g_api;

namespace detail {

constexpr std::uint32_t kMagic = 0x36485953u;  // 'SYH6'

// .syhk64 登记记录(SYR_HOOK 宏生成)。
// module 为空 => target 按绝对地址; 非空 => target 按 RVA, 安装时 base+rva。
struct HookDecl {
  std::uint32_t magic;
  std::uint32_t flags;         // 预留
  const wchar_t* module;
  std::uint64_t target;        // RVA 或绝对地址
  const char* name;            // 仅日志用
  void* detour;                // MinHook 式普通函数
  void** original;             // 可为 nullptr; 收到原函数跳板
};

}  // namespace detail
}  // namespace syr

// ---- 宏 API(对位 ra3-preinject 的 PREINJECT_HOOK 系列) -----------------------
#pragma section(".syhk64", read)
//   SYR_HOOK(L"GameAssembly.dll", 0x1234560, MyFn, &OrigMyFn)   模块 + RVA(推荐)
//   SYR_HOOK(nullptr, 0x7FF612340000, MyFn, nullptr)            绝对地址(逃生口)
#define SYR_HOOK(MODULE, RVA, DETOUR, ORIG)                                   \
  __declspec(allocate(".syhk64"))                                             \
  static syr::detail::HookDecl syr_decl_##DETOUR = {                          \
      syr::detail::kMagic, 0u, (const wchar_t*)(MODULE),                      \
      (std::uint64_t)(RVA), #DETOUR, (void*)(DETOUR), (void**)(ORIG)};

// ---- 内存写便捷宏(需要 g_api 已就绪, 即 SYR_PAYLOAD 之后) --------------------
#define SYR_MEM_WRITE(ADDR, BUF, LEN) \
  (syr::g_api ? syr::g_api->write_mem((std::uintptr_t)(ADDR), (BUF), (LEN)) : -1)

// ---- payload 入口 -----------------------------------------------------------
// 每个 payload 的一个 TU 里写一次; 牵引 load 时自动调用, 返回安装钩子数或负错。
#define SYR_PAYLOAD()                                                          \
  static syr::Api* syr_g_api_storage = nullptr;                                \
  namespace syr { Api* g_api = nullptr; }                                      \
  extern "C" __declspec(dllexport) int __cdecl SyrPayloadInit(const syr::Api* api) { \
    syr_g_api_storage = const_cast<syr::Api*>(api);                            \
    syr::g_api = syr_g_api_storage;                                            \
    HMODULE h = nullptr;                                                       \
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |                 \
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,        \
                       reinterpret_cast<LPCWSTR>(&SyrPayloadInit), &h);        \
    return api->install_section(h);                                            \
  }
