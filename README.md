# ctf-syringe64

面向 CTF 游戏客户端的 64 位注入与挂钩武器库。设计文档见 [DESIGN.md](DESIGN.md)。

## 架构（一期）

```
launcher64 ──注入──▶ 目标进程
                      └ syringe-tether.dll(常驻牵引: 命名管道控制面 + payload 热加载)
                          └ payload DLL ×N (SYR_HOOK 宏登记, MinHook 引擎)
syrctl / 任意客户端 ──管道──▶ \\.\pipe\syringe64-<pid>
```

- **引擎 = MinHook**（[TsudaKageyu/minhook](https://github.com/TsudaKageyu/minhook)，BSD-2，vendor 只读不修改）。
  本仓库不自研指令重定位/跳板：`MH_CreateHook + MH_EnableHook` 全权负责偷指令。
- **syr-core** 是 MinHook 之上的薄封装：`.syhk64` 登记段扫描安装、RVA→绝对地址解析（ASLR）、
  RWX 写原语、特征码扫描、日志、注入给 payload 的 API 函数指针表。
- **牵引（tether）** 常驻目标进程，行协议控制面（见下），支持运行期 freeze/thaw 全线程辅助安装。
- 所有钩子都是 **MinHook 式普通函数**，无汇编、无特殊调用约定。

## 快速上手

```powershell
# 构建 + 自测 + e2e(自动: puppet64 晚注入 → 宏 payload 三种篡改验证)
.\build.ps1

# 实战: 附着注入牵引
build\launcher64.exe --attach <pid> build\syringe-tether.dll
#   或创建即注入:  --create game.exe [args..] -- build\syringe-tether.dll

# 控制面(每个应答以单独 "." 行结束)
build\syrctl.exe <pid> hello
build\syrctl.exe <pid> modules
build\syrctl.exe <pid> read 7ff612340000 20
build\syrctl.exe <pid> write 7ff612340000 90909090
build\syrctl.exe <pid> scan GameAssembly.dll "48 89 5C 24 ?? 57"
build\syrctl.exe <pid> load D:\ctf\payload.dll
build\syrctl.exe <pid> hooks
build\syrctl.exe <pid> log
build\syrctl.exe <pid> freeze | thaw
```

## 编写 payload（赛场模板见 example/payload_example.cpp）

```cpp
#include "syringe.hpp"

// 1) 函数入口牵引 + 参数篡改(=reg 篡改): 模块 + RVA, ASLR 安全
static long long (*OrigAdd)(long long, long long);
static long long D_Add(long long a, long long b);
SYR_HOOK(L"GameAssembly.dll", 0x1234560, D_Add, &OrigAdd)
static long long D_Add(long long a, long long b) { return OrigAdd(a, b + 100); }

// 2) 跳过逻辑: 不调原函数, 直接返回(ORIG 传 nullptr)
static long long D_Secret(long long);
SYR_HOOK(L"GameAssembly.dll", 0x1234800, D_Secret, nullptr)
static long long D_Secret(long long) { return 0x1337; }

// 3) 任意地址牵引: 把地址 cast 成函数指针替代 original 调用
static long long D_Flow(long long);
SYR_HOOK(L"GameAssembly.dll", 0x1234A00, D_Flow, nullptr)
static long long D_Flow(long long x) {
  return ((long long (*)(long long))0x7FF612399000)(x);   // 直达任意代码处
}

SYR_PAYLOAD()   // 每个 payload 写一次; 牵引 load 时自动安装全部宏钩子
```

其他能力速查（无需引擎支持，纯 Win64 调用约定事实）：

| 能力 | 写法 |
| --- | --- |
| 栈参数（第 5+ 参）篡改 | detour 签名直接声明这些参数，改完调 original |
| 返回地址 | `#include <intrin.h>` 后 `_ReturnAddress()` |
| 内存写 | `SYR_MEM_WRITE(addr, bytes, n)` / `g_api->write_mem` |
| 特征码定位 | `g_api->scan(L"module", "48 8B ??", out, n)` |
| 日志 | `g_api->log("hit a=%lld", a)` → `syrctl <pid> log` 查看 |

编译：`cl /LD /O2 /std:c++17 /Iinclude payload.cpp`（建议 `/MT` 静态 CRT）。
RVA 全 0 时安装自动跳过，可先做编译检查。

## 测试

- `build\selftest.exe`：本进程 MinHook 挂钩自测（参数/栈参篡改、跳过返回、任意地址调用、写原语、扫描、登记段、卸载还原）。
- `test\e2e.ps1`：puppet64 晚注入端到端——附着注入 → 控制面 → 编译期注入 RVA 的宏 payload 热加载 →
  `add 1 2→103`、`secret→1337`、`flow→2468`（任意地址牵引）→ freeze/thaw。

## 仓库结构

```
include/syringe.hpp     payload 作者唯一需要的头(宏 API + Api 表)
src/core/               MinHook 薄封装 + 注入 API 表
src/tether/             牵引 DLL(管道控制面 + payload 追加 + freeze/thaw)
src/launcher/           附着/创建两种投放模式
src/ctl/                syrctl 命令行客户端
test/                   puppet64 靶机 + selftest + e2e
example/                payload 模板
vendor/minhook/         MinHook 上游(BSD-2, 只读)
```

## 已知边界（后续版本）

- XMM 参数的 detour 签名照常可用（调用约定层面透明）。
- CFG 进程：优先钩函数入口；`SetProcessValidCallTargets` 适配在 DESIGN.md §6/§10 中排队。
- C#/Unity(Mono/IL2CPP JIT) 专项后续立项，见 DESIGN.md §10。
