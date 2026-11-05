// puppet_main.cpp —— 64 位测试靶: 打印基址与函数地址, stdin 命令循环。
//   命令: add <a> <b> | secret <x> | flow <x> | quit
// payload 通过宏(SYR_HOOK, 编译期 RVA)或运行时 API(配置文件)挂钩验证篡改效果。
#include <windows.h>
#include <cstdio>
#include <cstring>

extern "C" __declspec(dllexport, noinline) long long PuppetAdd(long long a, long long b) {
  return a + b;  // 未挂钩时应答 a+b
}

extern "C" __declspec(dllexport, noinline) long long PuppetSecret(long long x) {
  // "机密"函数: 未挂钩时返回 x^K; 钩子若 ret_with(0x1337) 则跳过
  return x ^ 0x5A5A5A5A5A5A5A5All;
}

extern "C" __declspec(dllexport, noinline) long long PuppetFlow(long long x) {
  // 分段函数: 供 jump_to 跳段验证 —— 正常返回 x*10+3
  long long a = x * 2;          // seg A
  long long b = a + 1;          // seg B
  long long c = b * 5 - 2;      // seg C  (=(x*2+1)*5-2 = 10x+3)
  return c;
}

extern "C" __declspec(dllexport, noinline) long long PuppetAlt(long long x) {
  return 0x2468 + (x & 0);   // 未挂钩: 任意地址牵引的目的地
}

static void* AddrOf(void* fn) { return fn; }

int main(void) {
  HMODULE base = GetModuleHandleW(nullptr);
  printf("BASE=%p\n", (void*)base);
  printf("ADD=%p\n", AddrOf((void*)PuppetAdd));
  printf("SECRET=%p\n", AddrOf((void*)PuppetSecret));
  printf("FLOW=%p\n", AddrOf((void*)PuppetFlow));
  printf("ALT=%p\n", AddrOf((void*)PuppetAlt));
  printf("PID=%lu\n", GetCurrentProcessId());
  fflush(stdout);

  if (getenv("PUPPET_HOLD")) {  // create 模式冒烟用: 无 stdin 环境下驻留
    Sleep(30000);
    return 0;
  }

  char line[256];
  while (fgets(line, sizeof(line), stdin)) {
    char cmd[64] = "";
    long long a = 0, b = 0;
    sscanf(line, "%63s %lld %lld", cmd, &a, &b);
    if (!strcmp(cmd, "quit")) break;
    if (!strcmp(cmd, "add")) printf("add=%lld\n", PuppetAdd(a, b));
    else if (!strcmp(cmd, "secret")) printf("secret=%llx\n", PuppetSecret(a));
    else if (!strcmp(cmd, "flow")) printf("flow=%llx\n", PuppetFlow(a));
    else printf("?\n");
    fflush(stdout);
  }
  return 0;
}
