// selftest.cpp —— syringe-core 单机自测(本进程内 MinHook 式挂钩)。
// 覆盖: 参数(reg)篡改 / 栈参数(第5参)篡改 / 跳过+指定返回 / 任意地址牵引 /
//       RWX 写原语 / 特征码扫描 / 宏登记段安装 / 卸载。
#include <windows.h>
#include <cstdio>
#include <cstring>

#include "syringe.hpp"
#include "core_exports.hpp"

static int g_fail = 0;
static void Check(const char* what, long long got, long long want) {
  bool ok = got == want;
  printf("%-38s got=%llX want=%llX %s\n", what, got, want, ok ? "OK" : "FAIL");
  if (!ok) g_fail++;
}

// ---- 被测函数(防内联) ----
static __declspec(noinline) long long Add2(long long a, long long b) { return a + b; }
static __declspec(noinline) long long Secret(long long x) {
  return x ^ 0x5A5A5A5A5A5A5A5All;
}
static __declspec(noinline) long long SixArgs(long long a, long long b, long long c,
                                              long long d, long long e, long long f) {
  return e * 1000 + f;   // e 是第5参 => 栈上
}
static __declspec(noinline) long long FlowTest(long long x) { return x * 2 + 7; }
static __declspec(noinline) long long FlowJumpTarget(void) { return 0xCAFE; }

// ---- detours(MinHook 式普通函数) ----
static long long (*OrigAdd2)(long long, long long);
static long long D_Add2(long long a, long long b) { return OrigAdd2(a, b + 100); }

static long long D_Secret(long long) { return 0x1337; }  // 跳过: 不调原函数

static long long (*OrigSix)(long long, long long, long long, long long, long long, long long);
static long long D_Six(long long a, long long b, long long c, long long d,
                       long long e, long long f) {
  return OrigSix(a, b, c, d, 7, f);   // 栈参数(e)篡改
}

static long long D_Flow(long long x) {
  // 任意地址牵引: 不调原函数, 把目标地址 cast 成函数指针直接调用
  (void)x;
  return ((long long (*)(void))&FlowJumpTarget)();
}

// ---- 宏登记冒烟(模块为空 + 地址 0 => 安装时跳过, 验证段扫描不炸) ----
static long long D_MacroSmoke(long long);
static long long (*OrigMacroSmoke)(long long);
SYR_HOOK(nullptr, 0, D_MacroSmoke, &OrigMacroSmoke)
static long long D_MacroSmoke(long long x) { return x; }

int main(void) {
  setvbuf(stdout, nullptr, _IONBF, 0);
  if (SyrInit() != 0) { puts("core init FAIL"); return 1; }

  // 1. RWX 写原语
  static unsigned char buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  unsigned char patch[4] = {0x90, 0x90, 0x90, 0x90};
  SyrWriteMem((uintptr_t)buf, patch, 4);
  Check("write_mem", buf[0] == 0x90 && buf[3] == 0x90 && buf[4] == 5, 1);

  // 2. 特征码扫描(扫自身主模块, 找刚写入的 90 90 90 90)
  uintptr_t hits[8] = {};
  int n = SyrScanPattern(nullptr, "90 90 90 90 ?? 06", hits, 8);
  bool contains = false;
  for (int i = 0; i < n; i++) contains |= hits[i] == (uintptr_t)buf;
  Check("scan pattern hit", contains, 1);

  // 3. 参数(reg)篡改: b += 100 => Add2(1,2) == 103
  Check("Add2 unhooked", Add2(1, 2), 3);
  SyrHookRegister((uintptr_t)&Add2, (void*)&D_Add2, (void**)&OrigAdd2, "Add2");
  Check("arg tamper (b+100)", Add2(1, 2), 103);

  // 4. 跳过 + 指定返回
  SyrHookRegister((uintptr_t)&Secret, (void*)&D_Secret, nullptr, "Secret");
  Check("skip + return 0x1337", Secret(1), 0x1337);

  // 5. 栈参数篡改: 第5参 e -> 7 => 7*1000+f
  SyrHookRegister((uintptr_t)&SixArgs, (void*)&D_Six, (void**)&OrigSix, "SixArgs");
  Check("stack arg tamper (e=7)", SixArgs(0, 0, 0, 0, 3, 5), 7005);

  // 6. 任意地址牵引: FlowTest 钩子改调 FlowJumpTarget => 0xCAFE
  Check("FlowTest unhooked", FlowTest(10), 27);
  SyrHookRegister((uintptr_t)&FlowTest, (void*)&D_Flow, nullptr, "FlowTest");
  Check("arbitrary addr call", FlowTest(10), 0xCAFE);

  // 7. 宏登记段安装: 唯一记录地址为0, 应被跳过且不崩溃
  int r = SyrInstallSection((void*)GetModuleHandleW(nullptr));
  Check("macro section install (skip 0)", r >= 0, 1);

  // 8. 卸载还原
  Check("hook remove", SyrHookRemove((uintptr_t)&Add2), 0);
  Check("Add2 restored", Add2(1, 2), 3);

  printf("\n%s (hooks=%d)\n", g_fail ? "SELFTEST FAIL" : "SELFTEST PASS", SyrHookCount());
  return g_fail ? 1 : 0;
}
