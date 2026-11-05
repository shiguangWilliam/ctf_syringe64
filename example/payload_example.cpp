// payload_example.cpp —— 赛场 payload 模板: MinHook 式普通函数钩子全能力范例。
//
// 编译(e2e 会注入真实 RVA):
//   cl /LD /O2 payload_example.cpp /DPUPPET_ADD_RVA=0x.. /DPUPPET_SECRET_RVA=0x..
//      /DPUPPET_FLOW_RVA=0x.. /DPUPPET_JMP_ABS=0x..
// RVA 全为 0 时安装自动跳过(空钩子, 用于编译检查)。
#include "syringe.hpp"

#ifndef PUPPET_ADD_RVA
#define PUPPET_ADD_RVA 0
#endif
#ifndef PUPPET_SECRET_RVA
#define PUPPET_SECRET_RVA 0
#endif
#ifndef PUPPET_FLOW_RVA
#define PUPPET_FLOW_RVA 0
#endif
#ifndef PUPPET_JMP_ABS
#define PUPPET_JMP_ABS 0
#endif

// ---- 1) 函数入口牵引 + 参数篡改: 第2参 += 100, 照常执行原函数 ----
static long long (*OrigPuppetAdd)(long long, long long);
static long long D_PuppetAdd(long long a, long long b);
SYR_HOOK(L"puppet64.exe", PUPPET_ADD_RVA, D_PuppetAdd, &OrigPuppetAdd)
static long long D_PuppetAdd(long long a, long long b) {
  return OrigPuppetAdd(a, b + 100);
}

// ---- 2) 跳过整段逻辑, 直接按指定值返回(不调原函数) ----
static long long D_PuppetSecret(long long);
SYR_HOOK(L"puppet64.exe", PUPPET_SECRET_RVA, D_PuppetSecret, nullptr)
static long long D_PuppetSecret(long long) { return 0x1337; }

// ---- 3) 任意地址牵引: 不调原函数, 把目标地址 cast 成函数指针直接调用 ----
static long long D_PuppetFlow(long long);
SYR_HOOK(L"puppet64.exe", PUPPET_FLOW_RVA, D_PuppetFlow, nullptr)
static long long D_PuppetFlow(long long x) {
  (void)x;
  return ((long long (*)(long long))PUPPET_JMP_ABS)(1);
}

// ---- 其他能力速查 ----
// 栈参数篡改:  detour 签名直接声明第5+个参数, 改完调 original
// 返回地址:    #include <intrin.h> 后 _ReturnAddress()
// 内存写:      SYR_MEM_WRITE(addr, bytes, n) 或 g_api->write_mem
// 特征码扫描:  g_api->scan(L"module", "48 8B ??", out, n)
// 日志:        g_api->log("hit! a=%lld", a)

SYR_PAYLOAD()
