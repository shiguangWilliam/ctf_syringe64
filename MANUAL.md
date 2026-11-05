# ctf-syringe64 使用说明书

> 64 位 Windows 游戏客户端通用注入与挂钩武器库。引擎 = MinHook（BSD-2，vendor 只读）；
> 本说明书对应 v6（Api 表版本 6 / `SYR_API_MIN` 3）。
> 配套文档：[DESIGN.md](DESIGN.md)（总体设计）· [DESIGN-UNITY.md](DESIGN-UNITY.md)（RWX/托管策略）· [README.md](README.md)（速览）

---

## 1. 编译产物清单（`build\`）

| 文件 | 作用 | 何时使用 |
| --- | --- | --- |
| `launcher64.exe` | 启动壳：把牵引 DLL 送进目标 | 每次开始操作 |
| `syringe-tether.dll` | 常驻牵引：双控制面（管道 + Web UI）+ 全部原语 + payload 热加载 | 由 launcher 注入，你不直接运行 |
| `syrctl.exe` | 命令行客户端 | 脚本化操作 / 无浏览器环境 |
| `puppet64.exe` / `selftest.exe` | 测试靶机 / 自测程序 | 验证环境、学习命令 |
| `e2e_payload*.dll` | e2e 生成的样例 payload | 参考 |

**环境要求**：Windows 10/11 x64；构建需 VS BuildTools 2026（x64 工具链），运行无任何额外依赖（payload 建议 `/MT` 静态 CRT）。

**构建**：仓库根目录 `powershell -ExecutionPolicy Bypass -File build.ps1`
（编译 → 45 项自测 → e2e 端到端 → create 冒烟，任何一步失败即中止并报错）。

---

## 2. 快速上手（5 分钟）

```powershell
# 1) 注入(进程已在跑)
build\launcher64.exe --attach <pid> build\syringe-tether.dll
#   或游戏未启动: 创建即注入(挂起创建→注入→恢复)
build\launcher64.exe --create "C:\game\game.exe" [args..] -- build\syringe-tether.dll

# 2) 验证 + 打开控制面
build\syrctl.exe <pid> hello
# 浏览器打开(端口 = 18700 + pid % 256, hello 会回报):
#   http://127.0.0.1:<port>

# 3) 定位目标(按已知信息选一路)
build\syrctl.exe <pid> modules                              # 看模块基址(ASLR)
build\syrctl.exe <pid> export <GameAssembly基址> FuncName   # 剥导出 DLL 也能解析
build\syrctl.exe <pid> pe <模块基址>                        # 段表: 可执行块范围
build\syrctl.exe <pid> scan GameAssembly.dll "48 89 5C 24 ?? 57"   # 模块内特征码
build\syrctl.exe <pid> scanrwx "48 8D 04"                   # 全进程堆上 RWX(JIT 产物)
build\syrctl.exe <pid> scanrange <start> <end> "<pat>"      # 指定区间

# 4) 加载攻击 payload(满足宏约定即可, 注入器永不重编)
build\syrctl.exe <pid> load D:\ctf\payload.dll
build\syrctl.exe <pid> hooks      # 查看已装钩子
build\syrctl.exe <pid> log        # 引擎/牵引/payload 日志
```

---

## 3. 命令参考（管道与 Web UI 同构）

所有应答为多行文本，以单独 `.` 行结束。地址一律十六进制绝对地址（`0x` 可省）。

| 命令 | 说明 |
| --- | --- |
| `hello` | 版本 / pid / 位数 / Web UI 地址 |
| `modules` | 全模块表：`基址 大小 路径` |
| `read <addr> <len>` | 内存读（≤2048 字节，安全） |
| `write <addr> <hexbytes>` | 内存写（RWX 原语：改保护→写→还原→刷 I-cache） |
| `scan <module\|*> "<pattern>"` | 模块内特征码扫描，`??` 为通配 |
| `scanrwx "<pattern>"` | **全进程私有可执行页扫描**（JIT 产物/运行期 stub 定位） |
| `scanrange <start> <end> "<pattern>"` | 指定区间扫描 |
| `pe <addr>` | 任意已加载 DLL 的段表（含 exec 标记） |
| `export <addr> <name>` | 自解析导出表 → 函数 VA（剥加载器/手动映射场景仍可用） |
| `load <dll绝对路径>` | 加载 payload 并自动调 `SyrPayloadInit` |
| `hooks` | 已装钩子列表 |
| `log` | 引擎日志（安装结果/错误/状态码） |
| `freeze` / `thaw` | 冻结/恢复其他全部线程（装钩子辅助） |
| `alloc <len> [exec]` | 进程内分配（exec=1 → RWX），返回地址 |
| `free <addr>` | 释放 |
| `cfgset <addr>` | 把地址写入 CFG 白名单位图（见 §7） |
| `quit` | 关闭本连接（牵引常驻） |

## 4. Web UI

- 地址：`http://127.0.0.1:18700+pid%256`，仅回环绑定。
- 布局：status / hooks / modules / log 四窗自动刷新（2s）+ 命令控制台（Enter 执行）。
- 接口：`GET /api/exec?c=<urlencoded 命令>`——与管道完全同一命令面，可被任意外部工具（含你的 pythonbin 流水线）直接 HTTP 调用。

---

## 5. payload 编写手册

payload = 普通 x64 DLL + 本仓库 `include/syringe.hpp`，**不链接引擎**。
赛场攻击逻辑全在这里；注入器永不因 payload 变化而重编。

```cpp
#include "syringe.hpp"

// ---- 钩子 1: 函数入口牵引 + 参数篡改(模块 + RVA, ASLR 安全) ----
static long long (*OrigAdd)(long long, long long);
static long long D_Add(long long a, long long b);
SYR_HOOK(L"GameAssembly.dll", 0x1234560, D_Add, &OrigAdd)
static long long D_Add(long long a, long long b) { return OrigAdd(a, b + 100); }

// ---- 钩子 2: 跳过整段逻辑直接返回(ORIG 传 nullptr) ----
static long long D_Secret(long long);
SYR_HOOK(L"GameAssembly.dll", 0x1234800, D_Secret, nullptr)
static long long D_Secret(long long) { return 0x1337; }

// ---- 钩子 3: 任意地址牵引(把地址 cast 成函数指针替代 original) ----
static long long D_Flow(long long);
SYR_HOOK(L"GameAssembly.dll", 0x1234A00, D_Flow, nullptr)
static long long D_Flow(long long x) {
  return ((long long (*)(long long))0x7FF612399000)(x);   // 直达任意代码处
}

SYR_PAYLOAD()   // 每个 payload 一个 TU 写一次
```

**能力速查**（全部普通 C++，无汇编/特殊约定）：

| 需求 | 写法 |
| --- | --- |
| 参数/寄存器篡改 | detour 改形参后调 `original` |
| 栈参数(第5+参)篡改 | detour 签名直接声明这些参数 |
| 跳过逻辑 | 不调 `original`，直接 `return` 指定值 |
| 任意地址调用/直入某段 | `((RET(*)(ARGS))addr)(...)` |
| 返回地址 | `<intrin.h>` 的 `_ReturnAddress()` |
| 内存读写/分配 | `SYR_MEM_READ/WRITE`、`SYR_ALLOC(size,exec)`、`SYR_PROTECT` |
| 运行时登记钩子 | `g_api->hook_register(绝对地址, detour, &orig, "名")` |
| 特征码定位 | `g_api->scan(L"mod","48 8B ??",out,n)` / `scan_rwx` / `scan_range` |
| 按名取剥导出 DLL 函数 | `g_api->pe_export(base, "Name")` |
| 段表 | `g_api->pe_sections(base, out, n)` |
| CFG 放行 | `g_api->cfg_validate(addr,len)` / `cfg_bitmap_set(addr)` |
| 日志 | `g_api->log("hit a=%lld", a)` → `syrctl <pid> log` 或 Web UI |
| 自定义初始化 | `SYR_PAYLOAD_WITH_INIT(MyInit)`（返回负值则整体报错） |

**编译**：`cl /LD /O2 /MT /std:c++17 /Iinclude payload.cpp`（`/MT` 必须）。
RVA 全 0 时安装自动跳过——可先做编译检查。

**版本契约**：payload 编译时锁定 `SYR_API_MIN`；旧注入器装新 payload 返回 `-100`
（明确报错而非未定义行为）。引擎新能力只在 Api 表尾部追加。

---

## 6. 目标形态 → 操作路径速查

| 目标 | 定位 | 钩取 |
| --- | --- | --- |
| native 引擎函数（IDA 可逆 sub_） | IDA 拿 RVA → `SYR_HOOK(模块,RVA)` | MinHook |
| IL2CPP C# 方法 | Il2CppDumper+IDA → RVA → 同上 | 同上 |
| 剥导出/手动映射 DLL | `pe <base>` 拿可执行块 → `export`/`scanrange` | 同上 |
| Mono JIT 产物（离线无地址） | dnSpy 看逻辑 → 特征码 → `scanrwx`；或 payload 内自解析 mono（见 `example/mono_resolve_recipe.cpp`） | 同上（引擎对任意可执行地址同构） |
| 运行期生成代码/加密 stub | `alloc exec` + `write` + cast 调用 | detour 内调用 |
| 数据段/虚表 | `read`/`write`（保护自动往返） | — |

## 7. CFG 说明（实测结论）

- MinHook 函数头 patch **不受 CFG 影响**（patch 的就是位图内合法目标）。
- 仅「任意地址 cast 调用 / 动态生成 stub 执行」可能受检。`cfg_validate` 三级兜底：
  官方 API（kernel32→kernelbase→ntdll 链式解析）→ 位图直写（`cfg_bitmap_set`：
  ntdll 索引指针定位 + `bit=(addr>>3)&63, byte=base[addr>>9]` 公式置位）→ 记日志放行。
- 状态码：`0` 成功 `1` 未开 CFG `2` 位图定位失败（**新 Windows 已内核化，用户态无位图，
  实测此形态下 CFG 不拦我们的调用**）`3` 写失败。

## 8. 故障排除

| 症状 | 原因与处置 |
| --- | --- |
| `open pipe failed` | 牵引未注入成功：查 launcher 输出；目标可能带保护，改 `--create` 或补手动映射 |
| `hello` 无响应 | 目标主线程冻结/卡死；或端口/管道被占用 |
| `LOAD -100` | 注入器 Api 版本低于 payload 编译时 `SYR_API_MIN` —— 升级注入器 |
| `ERR access`（read） | 地址不可读（SEH 拦截），检查模块基址是否过期（重扫 `modules`） |
| 钩子 `ALREADY` | 同地址重复登记；`hooks` 查看 |
| 目标崩溃于装钩后 | 用 `freeze` → 装钩 → `thaw`；确保钩在函数入口（非任意指令中间） |
| `LOAD -1`（gle=126） | **实测(WCE)：部分游戏按“线程创建来源”拦截进程内 LdrLoadDll**——牵引内 LoadLibrary 全拒，但 launcher 的 `CreateRemoteThread` 畅通。对策：payload 用**自举模式**（见 `example/payload_wce_test.cpp`：DllMain 起线程，`GetModuleHandleW(L"syringe-tether.dll")` + `SyrGetApi` 取 Api 表自行初始化），由 `launcher64 --attach` 外部装载 |
| 注入返回 NULL（路径正确） | 部分游戏只允许从**自身目录**加载 DLL（WCE 实测）：把 tether/payload 拷进游戏目录再注入 |
| 重载同一 payload 无反应 | 模块已在进程内，DllMain 不会重触发；换文件名或重启目标 |
| `scanrwx`/`scanrange` 空 | 起点可能落在未提交页（SEH 跳过）；mono JIT 序言与 MSVC 不同，先用 `read` 取目标真实字节再当特征 |

## 9. 架构与安全边界

```
launcher64 ──注入──▶ 目标进程
                      └ syringe-tether.dll(常驻: 管道 + Web UI + 原语 + payload 热加载)
                          └ payload DLL ×N(SYR_HOOK 宏, MinHook 引擎, Api 函数指针表)
syrctl / 浏览器 / pythonbin 流水线 ──管道或 HTTP──▶ 同一命令面
```

- 仅面向本地授权 CTF 目标；不内置任何对服务器/基础设施的攻击能力。
- Web UI 只绑 127.0.0.1；管道本地命名对象。
- 所有写操作留有日志；钩子可卸载还原（`hook_remove` 恢复原字节）。

## 10. 测试矩阵（本次交付实测）

- `selftest.exe`：**45 项断言**——参数/栈参篡改、跳过返回、任意地址调用、JIT 模拟
  （RWX 生成代码→钩→篡改→还原）、`scan_rwx` 双命中、读写原语、保护往返、PE 段表、
  导出自解析（与 GetProcAddress 逐字节一致）、区间扫描、负例（ALREADY/野地址/删不存在）、
  CFG、版本契约。
- `e2e.ps1`：附着注入 → 管道+Web 双控制面 → 宏 payload（参数篡改/跳过返回/任意跳转
  三行为验证）→ 内存链路 alloc→write→read 回读 → 第二 payload 热加载 → freeze/thaw。
- `e2e_create.ps1`：`--create` 冒烟（挂起创建→注入→恢复→双控制面握手）。
