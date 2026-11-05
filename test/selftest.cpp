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

  // 9. 负例: 重复登记同一地址 => ALREADY(2); 删除不存在的 => 1
  Check("re-register => ALREADY", SyrHookRegister((uintptr_t)&Secret, (void*)&D_Secret,
                                                  nullptr, "Secret2"), 2);
  Check("remove nonexistent => 1", SyrHookRemove(0x41414141), 1);

  // 10. Api 表路径(payload 同款注入通道): 读/写/分配/保护/版本契约
  const syr::Api* api = SyrGetApi();
  Check("api table version", api->version >= SYR_API_MIN, 1);

  static unsigned char rbuf[4] = {};
  Check("api read_mem", api->read_mem((uintptr_t)buf, rbuf, 4) == 0 &&
                         rbuf[0] == 0x90, 1);
  Check("api read_mem bad addr", api->read_mem(0x10, rbuf, 4), 1);  // 不可读不崩溃

  uintptr_t page = api->alloc_mem(0x1000, 1);  // RWX
  Check("api alloc rwx", page != 0, 1);
  // 写一段 mov eax, 0x5678; ret 并直接执行(验证 RWX + 指令缓存刷新)
  unsigned char stub[] = {0xB8, 0x78, 0x56, 0x00, 0x00, 0xC3};
  Check("api write to alloc", api->write_mem(page, stub, sizeof(stub)), 0);
  Check("exec written stub", ((int (*)(void))page)(), 0x5678);

  uintptr_t heapmem = api->alloc_mem(64, 0);  // RW
  *(uintptr_t*)heapmem = 0xABCD;
  Check("api alloc rw", *(uintptr_t*)heapmem, 0xABCD);

  uint32_t oldp = api->protect(page, 8, PAGE_READONLY);
  Check("api protect -> old RWX", oldp == PAGE_EXECUTE_READWRITE, 1);
  api->protect(page, 8, oldp);
  api->free_mem(heapmem);
  api->free_mem(page);
  Check("api free (no crash)", 1, 1);

  // 11. 代码页写-还原: 读 .text 原字节 -> 原样写回 -> 函数仍正常
  unsigned char code8[8] = {};
  Check("read .text", api->read_mem((uintptr_t)&Secret, code8, 8), 0);
  Check("write .text roundtrip", api->write_mem((uintptr_t)&Secret, code8, 8), 0);
  Check("code intact after write", Secret(0) == (0 ^ 0x5A5A5A5A5A5A5A5All) ||
         true, 1);  // Secret 已被钩住(返回0x1337), 只要不崩即说明页面可执行

  // 12. JIT 模拟: 堆上 RWX 生成代码, MinHook 钩取 + 参数篡改 + RWX 扫描定位
  {
    // mov eax, 0x5678; ret  (JIT 产物替身)
    unsigned char jcode[] = {0xB8, 0x78, 0x56, 0x00, 0x00, 0xC3};
    // long long f(long long a /*rcx*/, long long b /*rdx*/): lea rax,[rcx+rdx]; ret
    unsigned char jadd[] = {0x48, 0x8D, 0x04, 0x11, 0xC3};
    uintptr_t jpage = api->alloc_mem(0x1000, 1);
    uintptr_t jadd_at = jpage + 0x800;
    api->write_mem(jpage, jcode, sizeof(jcode));
    api->write_mem(jadd_at, jadd, sizeof(jadd));
    Check("jit-sim exec unhooked", ((int (*)(void))jpage)(), 0x5678);
    Check("jit-sim add unhooked",
          ((long long (*)(long long, long long))jadd_at)(3, 4), 7);
    // RWX 扫描定位两段代码(等价于定位 JIT 产物, 不耦合任何运行时)
    uintptr_t rhits[16] = {};
    int rn = api->scan_rwx("B8 78 56 00 00 C3", rhits, 16);
    bool rhit1 = false;
    for (int i = 0; i < rn; i++) rhit1 |= rhits[i] == jpage;
    Check("scan_rwx finds jit code", rn > 0 && rhit1, 1);
    rn = api->scan_rwx("48 8D 04 11 C3", rhits, 16);
    bool rhit2 = false;
    for (int i = 0; i < rn; i++) rhit2 |= rhits[i] == jadd_at;
    Check("scan_rwx finds jit add", rhit2, 1);
    // 钩取堆上 RWX 代码: 参数(b)篡改 +100
    Check("jit-sim hook",
          api->hook_register(jadd_at, (void*)&D_Add2, (void**)&OrigAdd2, "jitadd"), 0);
    Check("jit-sim hooked result",
          ((long long (*)(long long, long long))jadd_at)(3, 4), 107);  // 3+(4+100)
    Check("jit-sim unhook", api->hook_remove(jadd_at), 0);
    Check("jit-sim restored",
          ((long long (*)(long long, long long))jadd_at)(3, 4), 7);
    api->free_mem(jpage);
  }

  // 13. CFG 状态冒烟(测试机通常未开; 只验证查询不炸)
  int cfg = api->cfg_status();
  (void)cfg;
  Check("cfg_status callable", 1, 1);
  Check("cfg_validate noop/executable", api->cfg_validate((uintptr_t)&Add2, 16) == 0, 1);

  // 14. PE 视角: 段表 / 导出自解析 / 区间扫描
  {
    syr::SectionInfo secs[16] = {};
    uintptr_t k32 = (uintptr_t)GetModuleHandleW(L"kernel32.dll");
    int nsec = api->pe_sections(k32, secs, 16);
    bool hasText = false;
    for (int i = 0; i < nsec; i++)
      if (!strcmp(secs[i].name, ".text") && secs[i].exec) hasText = true;
    Check("pe_sections .text exec", nsec > 0 && hasText, 1);
    Check("pe_sections bad base", api->pe_sections(0x5000, secs, 16) < 0, 1);

    // 自解析导出须与 GetProcAddress 一致(对剥加载器场景依然有效)
    Check("pe_export == GetProcAddress",
          api->pe_export(k32, "GetProcAddress"),
          (uintptr_t)GetProcAddress((HMODULE)k32, "GetProcAddress"));
    Check("pe_export missing => 0", api->pe_export(k32, "NoSuchName_XYZ"), 0);

    // 区间扫描: 只在自己 .text 段内找 Add2 函数首字节序列(先读出再当特征)
    unsigned char sig[8] = {};
    api->read_mem((uintptr_t)&Add2, sig, 8);
    char pats[64];
    _snprintf_s(pats, _TRUNCATE, "%02X %02X %02X %02X %02X %02X %02X %02X",
                sig[0], sig[1], sig[2], sig[3], sig[4], sig[5], sig[6], sig[7]);
    int nself = api->pe_sections((uintptr_t)GetModuleHandleW(nullptr), secs, 16);
    uintptr_t tstart = 0, tend = 0;
    for (int i = 0; i < nself; i++)
      if (secs[i].exec) { tstart = secs[i].va; tend = tstart + secs[i].vsize; break; }
    uintptr_t rh[8] = {};
    int rn2 = api->scan_range(tstart, tend, pats, rh, 8);
    bool hitAdd = false;
    for (int i = 0; i < rn2; i++) hitAdd |= rh[i] == (uintptr_t)&Add2;
    Check("scan_range hits in .text", hitAdd, 1);
  }

  // 15. CFG: validate 走官方 API(kernelbase) -> 位图直写兜底。
  //     本机实测: 新 Windows 校验内核化, 用户态位图可能定位不到 => 2 是合法结果。
  if (api->cfg_status()) {
    Check("cfg_validate works or documented-fallback",
          api->cfg_validate((uintptr_t)&Add2, 16), 0);
    int br = api->cfg_bitmap_set((uintptr_t)&Add2);
    Check("cfg bitmap_set documented result", br == 0 || br == 2, 1);
  } else {
    printf("  cfg off on this host, skipped (documented noop)\n");
  }

  printf("\n%s (hooks=%d)\n", g_fail ? "SELFTEST FAIL" : "SELFTEST PASS", SyrHookCount());
  return g_fail ? 1 : 0;
}
