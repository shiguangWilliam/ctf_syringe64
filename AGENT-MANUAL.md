# ctf-syringe64 Agent 操作手册

> 面向后续 Agent 的实战手册：从注入、命令面、宏 API、payload 编写，到 Unity/C# 场景与故障排查。
> 依据：本仓库源码 + `README.md` / `MANUAL.md` / `DESIGN-UNITY.md` + `audit/REPORT.md` 的实测结论。
> 适用：Windows x64 本地授权 CTF 目标。**不覆盖** Linux/macOS、内核对抗、受保护进程。
> 版本：tether/core `SYR_VERSION 6`，`SYR_API_MIN 3`；与 `audit/REPORT.md` 同批次代码。

---

## 目录

1. [60 秒快速开始](#1-60-秒快速开始)
2. [架构与进程模型](#2-架构与进程模型)
3. [环境、构建与产物](#3-环境构建与产物)
4. [Agent 交互契约（必读红线）](#4-agent-交互契约必读红线)
5. [命令参考（完整）](#5-命令参考完整)
6. [注入器使用](#6-注入器使用)
7. [Payload 编写（宏 + API）](#7-payload-编写宏--api)
8. [Unity / C# 场景](#8-unity--c-场景)
9. [完整工作流与配方](#9-完整工作流与配方)
10. [故障排查矩阵](#10-故障排查矩阵)
11. [已知缺陷与规避](#11-已知缺陷与规避)
12. [Agent 操作检查清单](#12-agent-操作检查清单)
13. [附录](#13-附录)

---

## 1. 60 秒快速开始

假设目标已在运行、PID 为 `<pid>`，所有路径**不含空格**。

```powershell
# 1) 注入牵引（注入桥；只需一次）
D:\ctf\ctf-syringe64\build\launcher64.exe --attach <pid> D:\ctf\ctf-syringe64\build\syringe-tether.dll

# 2) 握手（launcher 返回后管道可能还没就绪，重试 1~3 次）
D:\ctf\ctf-syringe64\build\syrctl.exe <pid> hello
# 期望：syringe64 tether v6 pid=<pid> bits=64 web=http://127.0.0.1:<18700+pid%256>

# 3) 加载“用了宏 API 的 DLL”（绝对路径、无空格）
D:\ctf\ctf-syringe64\build\syrctl.exe <pid> load D:\ctf\payloads\my_payload.dll
# 期望：LOAD <安装的宏钩子数>；0=无钩子/已装过，-1=加载失败，-100=牵引 API 版本过低

# 4) 查看钩子与日志
D:\ctf\ctf-syringe64\build\syrctl.exe <pid> hooks
D:\ctf\ctf-syringe64\build\syrctl.exe <pid> log

# 5) 验证目标行为（按你的 payload 设计）
```

**最小验证闭环**（仓库自带靶机，建议先跑一次确认环境）：

```powershell
# 终端 A：启动靶机，记下 banner 里的 PID
D:\ctf\ctf-syringe64\build\puppet64.exe

# 终端 B：注入 + 加载 e2e 宏 payload（e2e 会按当前靶机 RVA 编译）
powershell -ExecutionPolicy Bypass -File D:\ctf\ctf-syringe64\test\e2e.ps1
```

---

## 2. 架构与进程模型

```
launcher64.exe ──注入──▶ 目标进程
                          └ syringe-tether.dll（常驻牵引）
                              ├ 命名管道：\\.\pipe\syringe64-<pid>（单连接、行协议）
                              ├ 本地 HTTP：127.0.0.1:<18700+pid%256>（/、/api/exec）
                              └ payload DLL ×N（SYR_HOOK 宏登记，MinHook 引擎）

syrctl / 浏览器 / Python ──管道或 HTTP──▶ 同一命令面
```

| 组件 | 作用 | 关键事实 |
| --- | --- | --- |
| `launcher64.exe` | 把 tether 送进目标 | `--attach` / `--create`；只负责注入，不做安装 |
| `syringe-tether.dll` | 常驻控制面 + 写原语 + payload 热加载 | 管道 + HTTP 双控制面；`load` 调 `SyrPayloadInit` |
| `syrctl.exe` | 管道客户端 | 一次性命令 / `-` 交互；应答以 `.` 行结束 |
| payload DLL | 赛场逻辑 | 只 include `syringe.hpp`，**不链接引擎**；`SYR_PAYLOAD` 导出入口 |
| 引擎 | MinHook | `.syhk64` 登记段扫描 + `hook_register`；x64 指令重定位由 MinHook 负责 |

**payload 生命周期**：

1. `load <abs path>` → tether `LoadLibraryW`（在本地 `CreateThread` 中执行，规避部分游戏的线程来源检查）。
2. 找到导出 `SyrPayloadInit` → 调 `SyrPayloadInit(&Api)`。
3. `SYR_PAYLOAD` 里：版本检查 → 保存 `g_api` → `install_section(本模块)`。
4. `install_section` 扫描 `.syhk64` 段中每条 `HookDecl` → `hook_register(base+RVA, detour, &orig)`。
5. 返回安装数量（即 `LOAD n`）。
6. **卸载不提供**：没有 `unload` 命令；要撤销只能 payload 自己 `hook_remove`，或重启目标。

---

## 3. 环境、构建与产物

### 3.1 环境

- Windows 10/11 **x64**（本手册不含 x86）。
- 构建：VS BuildTools（本机 `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools`），x64 工具链。
- 目标标准：**C++17**（`build.ps1` 全部 TU 使用 `/std:c++17`）。
- 运行：payload 建议 `/MT` 静态 CRT；`/source-charset:utf-8` 必加（头文件是 UTF-8 无 BOM，zh-CN 代码页下不加会 C2143）。

### 3.2 构建

```powershell
cd D:\ctf\ctf-syringe64
powershell -ExecutionPolicy Bypass -File build.ps1
```

构建会：编译 MinHook → core 静态库 → tether → launcher → syrctl → puppet → selftest → 跑 selftest（**42 项**）→ e2e → create 冒烟。

> 注意：`create 冒烟` 存在“假绿”（Web 检查失败仍打印 PASS），**不要只凭它判断成功**；见 §11。

### 3.3 产物（`build\`）

| 文件 | 用途 |
| --- | --- |
| `launcher64.exe` | 注入壳 |
| `syringe-tether.dll` | 牵引（控制面 + 热加载） |
| `syrctl.exe` | 命令行客户端 |
| `puppet64.exe` | 测试靶机 |
| `selftest.exe` | 进程内引擎自测（42 项） |
| `e2e_payload.dll` / `e2e_payload2.dll` | e2e 样例 payload |

### 3.4 目录约定（建议）

```
D:\ctf\
├─ ctf-syringe64\            # 本仓库
│  └─ build\                 # 产物
├─ payloads\                 # 你的 payload（路径不要有空格！）
└─ logs\                     # 会话日志
```

**路径规则**：`load` 的路径经 `sscanf` 取第一个空白分隔 token，**空格会截断**。payload 一律放在无空格路径（如 `D:\ctf\payloads\p1.dll`）。

---

## 4. Agent 交互契约（必读红线）

### 4.1 三种通道

| 通道 | 用法 | 特点 |
| --- | --- | --- |
| 管道一次性 | `syrctl.exe <pid> <命令...>` | 最简单；**单连接**；零命中扫描会挂死（§11） |
| 管道交互 | `syrctl.exe <pid> -` | 一个会话内多命令；空行会挂死，不要发空行 |
| HTTP | `GET http://127.0.0.1:<port>/api/exec?c=<URL编码命令>` | 扫描建议走这里；无鉴权，仅回环 |
| Web UI | `GET /` | 监控面板；自动刷新；可选 |

端口：`18700 + (pid % 256)`。`hello` 会回报实际端口，但**监听可能晚于 hello**，要重试。

### 4.2 应答协议

- 所有应答为多行文本，以**单独一行 `.`** 结束。
- 每个命令执行完才返回；HTTP 返回 `text/plain`，正文同样以 `.` 行结束。
- `syrctl`：应答以 `ERR` 开头时退出码为 `1`；成功 `0`；参数不足 `2`。
- **例外（缺陷）**：`scan`/`scanrwx`/`scanrange` 零命中时 tether 只回 `"."`（没有前导换行），`syrctl` 只认 `"\n."`，会永久阻塞。**扫描请走 HTTP**，或给 `syrctl` 包超时。

### 4.3 必须使用的超时包装（PowerShell）

```powershell
function Invoke-Syrctl {
  param([string]$Exe, [int]$TargetPid, [string[]]$CmdArgs, [int]$TimeoutMs = 8000)
  function Quote([string]$s) {
    if ($s -notmatch '[\s"]') { return $s }
    $sb = New-Object System.Text.StringBuilder; [void]$sb.Append('"'); $bs = 0
    foreach ($ch in $s.ToCharArray()) {
      if ($ch -eq '\') { $bs++; continue }
      if ($ch -eq '"') { [void]$sb.Append(('\' * (2 * $bs + 1)) + '"'); $bs = 0; continue }
      if ($bs -gt 0) { [void]$sb.Append('\' * $bs); $bs = 0 }
      [void]$sb.Append($ch)
    }
    if ($bs -gt 0) { [void]$sb.Append('\' * (2 * $bs)) }
    [void]$sb.Append('"'); return $sb.ToString()
  }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  $psi.Arguments = (($CmdArgs | ForEach-Object { Quote $_ }) -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
  $ok = $p.WaitForExit($TimeoutMs)
  if (-not $ok) { try { $p.Kill() } catch {}; [void]$p.WaitForExit(2000) }
  [pscustomobject]@{
    TimedOut = (-not $ok)
    Exit     = $(if ($ok) { $p.ExitCode } else { -1 })
    Out      = $(if ($o.Wait(2000)) { $o.Result } else { '' })
    Err      = $(if ($e.Wait(2000)) { $e.Result } else { '' })
  }
}

# 用法
$r = Invoke-Syrctl -Exe 'D:\ctf\ctf-syringe64\build\syrctl.exe' -TargetPid 1234 -CmdArgs @('hello')
if ($r.TimedOut) { Write-Host 'TIMEOUT: 客户端已杀，管道会自行恢复' }
```

### 4.4 HTTP 封装（PowerShell / Python）

```powershell
# $targetPid = 目标 PID
$port = 18700 + ($targetPid % 256)
$enc = [System.Uri]::EscapeDataString('scanrwx "48 8B 05 ?? ?? ?? ??"')
$r = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/api/exec?c=$enc" -TimeoutSec 8
$r.Content
```

```python
import urllib.parse, urllib.request

def web(port, cmd, timeout=8):
    url = f"http://127.0.0.1:{port}/api/exec?c={urllib.parse.quote(cmd)}"
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")
```

### 4.5 安全红线（不遵守会丢通道/砖化目标）

1. **不要用管道跑“可能 0 命中”的扫描** → 用 HTTP。若必须用管道，包超时；挂死后杀掉客户端，管道会恢复。
2. **不要在 payload/游戏线程可能写日志时 `freeze`** → 可能永久阻塞控制面，`thaw` 不可达（`gle=231`），只能杀目标。能不用就不用；MinHook 装钩自身会处理线程冻结。
3. **多 token 模式不要按 README 的分参写法**：`syrctl <pid> scanrwx "48 8B ..."` 会被空格重组、丢首字节/错位。要么整条命令作为一个 argv（`syrctl <pid> 'scanrwx "48 8B ..."'`），要么走 HTTP。
4. **不要信任 `create 冒烟` 的 PASS**：脚本失败时可能仍打印 PASS/exit 0；自己验证 `hello` 与 `/` 面板。
5. **不要重复 load 同一个 DLL 路径**：Windows 不会二次 DllMain，钩子会 `ALREADY`；要再装就换文件名或重启。
6. **不要发送空命令行**：tether 对空行不回复，客户端会挂。
7. **不要 hook 函数中间指令**：只 hook 函数入口；中间地址的指令重定位不可靠，可能崩目标。
8. **payload 路径不要有空格**；模块名不要加引号（`scan "puppet64.exe"` 会 `ERR scan`）。
9. **一次只用一个管道客户端**：管道单连接；并发会排队/`PIPE_BUSY`。
10. **目标保护/内核反作弊超出范围**；不要在未授权目标上使用。

---

## 5. 命令参考（完整）

> 所有地址为十六进制（`0x` 可省，大小写不敏感）；长度/计数为十进制（`alloc` 例外，见下）。
> 每条应答以 `.` 行结束；下表“限制”为代码实际行为，不是建议值。

### 5.1 会话

| 命令 | 说明 | 限制/注意 |
| --- | --- | --- |
| `hello` | 版本、pid、位数、Web 地址 | Web 可能尚未监听；重试 |
| `modules` | 全模块表：`基址 大小 路径` | 固定 `HMODULE[1024]`，>1024 模块越界（P2） |
| `quit` | 关闭本连接（tether 常驻） | 应答 `BYE`；不影响目标 |

`hello` 示例：

```
syringe64 tether v6 pid=45804 bits=64 web=http://127.0.0.1:18936
.
```

`modules` 示例（每行三列）：

```
00007ff72d030000 0004b000 D:\ctf\build\puppet64.exe
00007fff12340000 001f0000 C:\Windows\System32\ntdll.dll
...
.
```

### 5.2 内存

| 命令 | 语法 | 行为/限制 |
| --- | --- | --- |
| `read` | `read <addr> <len>` | `len` 1..2048；返回**大写** hex；不可读返回 `ERR access`（SEH 安全，不崩） |
| `write` | `write <addr> <hexbytes>` | 临时改 RWX→写→恢复→刷 I-cache；**实际最大 255 字节**（arg2 511 字符，奇数直接 `ERR args`）；跨未映射页 → `ERR write` |
| `alloc` | `alloc <len> [exec]` | `len` 用 **base-0** 解析：`4096`=十进制，`0x1000`=16 进制；`len=0` 默认 0x1000；`exec=1`→RWX，否则 RW；返回 16 位地址；页零初始化 |
| `free` | `free <addr>` | 必须 hex 解析；无效地址静默 `OK`（VirtualFree 失败不报） |
| `protect` | 无命令 | 只能用 payload 的 `g_api->protect` |

> 写大块数据：分多次 `write`，每次 ≤255 字节，地址递增。注意每次都会改保护/刷缓存。

### 5.3 扫描

| 命令 | 语法 | 行为/限制 |
| --- | --- | --- |
| `scan` | `scan <module\|*> "<pattern>"` | 模块内扫描；`*`=主模块；模式 `??`/`*` 通配；返回命中地址（最多 64）；**模块名不要加引号**；零命中→`"."`（管道挂死，见 §11） |
| `scanrwx` | `scanrwx "<pattern>"` | 全进程 `MEM_PRIVATE` 可执行页（JIT/跳板）；最多 64；同样零命中挂死 |
| `scanrange` | `scanrange <start> <end> "<pattern>"` | 指定区间；`start>=end` 或解析失败→`ERR scan`；同样零命中挂死 |

**模式语法**：十六进制字节**必须用空格分隔**，`??` 为单字节通配。

```text
48 8B 05 ?? ?? ?? ??     # 正确
488B05????????            # 错误：整串被当一个十六进制数截断
```

`scan` 示例：

```powershell
# 模块名不加引号，模式加引号
syrctl.exe <pid> scan puppet64.exe "48 8D 04 11 C3 CC CC CC"
# 00007ff72d031000
# .
```

`scanrwx` 的错误/正确姿势：

```powershell
# 错误（README 分参写法）：模式被截断成 "8B 05 ..."，命中 page+1
syrctl.exe <pid> scanrwx "48 8B 05 11 22 33 44"

# 正确 A：整条命令作为一个 argv（外层单引号）
syrctl.exe <pid> 'scanrwx "48 8B 05 11 22 33 44"'

# 正确 B：HTTP（推荐）
$enc=[Uri]::EscapeDataString('scanrwx "48 8B 05 11 22 33 44"')
Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/api/exec?c=$enc" | % Content
```

### 5.4 PE / 导出

| 命令 | 语法 | 行为/限制 |
| --- | --- | --- |
| `pe` | `pe <base>` | 段表：`name va vsize exec=0/1`；最多 32 段；非法基址 `ERR pe` |
| `export` | `export <base> <name>` | 自解析导出表 → VA（16 hex）或 `0`；名字不能有空格；转发导出返回 export 目录内地址 |

`pe` 示例：

```
.text    00007ff72d031000 00001000 exec=1
.rdata   00007ff72d032000 00002000 exec=0
...
.
```

### 5.5 Payload 生命周期

| 命令 | 语法 | 行为/限制 |
| --- | --- | --- |
| `load` | `load <dll绝对路径>` | 返回 `LOAD <n>`：`n≥0`=安装的宏钩子数；`0`=无钩子/已装过；`-1`=加载失败；`-100`=牵引 API 版本过低；路径不能有空格 |
| `hooks` | `hooks` | 每行 `%016llX name`；无钩子返回空行+`.` |
| `log` | `log` | 引擎/牵引/payload 日志（16KB 追加式，满了丢弃；无清空命令） |

`load` 示例：

```
LOAD 3
.
```

对应 `log`（典型）：

```
syr: core ready (ver 6, engine=MinHook)
tether: attached pid=45804
hook addr=00007FF72D031000 name=D_PuppetAdd OK tramp=00007FF72D020FC0
hook addr=00007FF72D031030 name=D_PuppetSecret OK tramp=0000000000000000
hook addr=00007FF72D031020 name=D_PuppetFlow OK tramp=0000000000000000
section: 3 hook(s) installed for module 00007FF86B1D0000
tether: payload D:\ctf\payloads\e2e_payload.dll init -> 3
.
```

### 5.6 线程冻结

| 命令 | 语法 | 行为/限制 |
| --- | --- | --- |
| `freeze` | `freeze` | 挂起除控制线程外全部线程；返回 `FROZEN <n>`；**可能死锁（§11）**；HTTP 线程也会被挂起 |
| `thaw` | `thaw` | 恢复全部其他线程；返回 `THAWED <n>`；**会恢复它没挂起的线程**（over-resume，§11） |

### 5.7 CFG

| 命令 | 语法 | 行为/限制 |
| --- | --- | --- |
| `cfgset` | `cfgset <addr>` | 把地址写入 CFG 白名单位图；返回 `CFGSET <code> base=<addr>`；code：`0`成功 `1`未开 CFG `2`位图定位失败 `3`写失败 |

> MinHook 的函数头 patch 不受 CFG 影响；只有“cast 调用任意地址/执行生成 stub”可能需要 `cfg_validate`/`cfg_bitmap_set`。

### 5.8 帮助/未知

| 输入 | 输出 |
| --- | --- |
| 未知命令 | `ERR unknown` |
| 空行 | **不回复**（客户端会挂；不要发） |
| 参数不足 | 对应 `ERR args` / `ERR read` 等 |

---

## 6. 注入器使用

### 6.1 `--attach`（进程已在跑）

```powershell
launcher64.exe --attach <pid> <tether.dll 绝对路径>
```

- 内部：`OpenProcess(PROCESS_ALL_ACCESS)` → `VirtualAllocEx` 写路径 → `CreateRemoteThread(LoadLibraryW)` → 等 10s → 释放。
- 输出 `inject OK (remote hmodule=...)`，退出 0。
- 失败：`OpenProcess failed gle=...` / `CreateRemoteThread failed` / `remote LoadLibraryW returned NULL`，退出 1。

**注意**：launcher 返回成功只代表 `LoadLibraryW` 返回非零；管道可能还要 30~60ms 才可用。`syrctl hello` 失败先重试。

### 6.2 `--create`（创建即注入）

```powershell
launcher64.exe --create "C:\game\game.exe" [args..] -- <tether.dll 绝对路径>
```

- `CREATE_SUSPENDED` 创建 → 注入 → `ResumeThread`；适合入口期装钩。
- `--` 之前是目标命令行，`--` 之后是 tether。
- **失败处理**：实测注入失败时 launcher 退出 1，但可能**遗留目标进程**（`CloseHandle` 后 `TerminateProcess` 的缺陷，见 §11）。失败后检查并清理：

```powershell
Get-Process <目标名> -ErrorAction SilentlyContinue | Stop-Process -Force
```

### 6.3 常见限制与对策

| 现象 | 原因 | 对策 |
| --- | --- | --- |
| `remote LoadLibraryW returned NULL` | 目标按“线程来源/路径/签名”拦截 | 把 tether/payload 复制到**游戏目录**再注入；或 payload 用自举模式（`example/payload_wce_test.cpp`：DllMain 起线程，`GetModuleHandleW("syringe-tether.dll")` + `SyrGetApi()` 自行初始化） |
| `OpenProcess failed gle=5` | 权限/完整性级别 | 以同用户/管理员运行；受保护进程放弃 |
| 注入成功但 `hello` 超时 | 管道未就绪/目标卡死 | 重试；检查目标是否冻结；查 `launcher` 输出 |
| 32 位目标 | 本工具 x64 | 换 x86 工具 |

> 手动映射（Manual Map）**未实现**；`DESIGN.md` 里的三模式是设计稿。

---

## 7. Payload 编写（宏 + API）

### 7.1 最小骨架

```cpp
#include "syringe.hpp"   // 唯一需要的头

// 1) 声明 original（可为 nullptr 表示不调用原函数）
static long long (*OrigAdd)(long long, long long);

// 2) 声明 detour（先声明后定义，SYR_HOOK 要取地址）
static long long D_Add(long long a, long long b);

// 3) 登记：模块名 + RVA（ASLR 安全）；ORIG 传 &OrigAdd
SYR_HOOK(L"GameAssembly.dll", 0x1234560, D_Add, &OrigAdd)

// 4) 定义 detour
static long long D_Add(long long a, long long b) {
  return OrigAdd(a, b + 100);   // 参数篡改后调原函数
}

// 5) 每个 payload 的一个 TU 写一次
SYR_PAYLOAD()
```

编译：

```bat
cl /LD /O2 /MT /std:c++17 /source-charset:utf-8 /EHsc /W3 /Iinclude payload.cpp /Fe:payload.dll
```

- `/MT`：静态 CRT，避免目标 CRT 版本不匹配。
- `/source-charset:utf-8`：**必加**（zh-CN 下否则 `syringe.hpp` 编译失败）。
- 只链接 `KERNEL32.dll`，不链接引擎/牵引。

### 7.2 宏展开与登记段

`SYR_HOOK(MODULE, RVA, DETOUR, ORIG)` 展开为：

```cpp
__declspec(allocate(".syhk64"))
static syr::detail::HookDecl syr_decl_##DETOUR = {
  magic /*'SYH6'*/, 0, (const wchar_t*)(MODULE),
  (uint64_t)(RVA), #DETOUR, (void*)(DETOUR), (void**)(ORIG)
};
```

`HookDecl`：`magic, flags, module, target, name, detour, original`（48 字节）。

- `module` 非空 → `target = module_base + RVA`；为空 → `target` 按绝对地址。
- **RVA=0 的记录会被安装器跳过**（`!d->target` 判断）。
- 模块名非空但模块未加载 → 当前实现会尝试 `0 + RVA`（见 §11 P2-2）；确保模块已加载。
- `.syhk64` 是只读段，运行时不要改。

### 7.3 入口宏

| 宏 | 行为 |
| --- | --- |
| `SYR_PAYLOAD()` | 版本检查（`< SYR_API_MIN` → `-100`）→ 保存 `g_api` → `install_section(本模块)` |
| `SYR_PAYLOAD_WITH_INIT(INIT)` | 先调 `INIT()`；**任意非 0 返回值**都会中止（文档写“负值”，代码是任意非 0），然后才 `install_section` |

> `g_api` 只在 `SyrPayloadInit` 之后有效；**不要**在 DllMain/静态初始化里用。

### 7.4 detour 签名规则（MS x64）

- 整数参数：`rcx, rdx, r8, r9`，第 5 个起在栈上；detour 直接声明这些参数即可篡改。
- 浮点：`XMM0..XMM3`；detour 用 `double/float` 形参，经 MinHook 跳板透明传递（实测）。
- 实例方法：第 1 个参数是 `this`。
- 返回值：直接返回目标类型；跳过时返回合法值。
- 栈/红区/对齐由编译器按 ABI 处理；不要写汇编。
- 不要在 detour 里抛 C++ 异常到目标代码；保持短小、避免阻塞。

### 7.5 六种常用配方

**A. 参数/寄存器篡改**

```cpp
static long long (*Orig)(long long, long long);
static long long Det(long long a, long long b);
SYR_HOOK(L"game.exe", 0x1234, Det, &Orig)
static long long Det(long long a, long long b) { return Orig(a, b + 100); }
```

**B. 跳过整段逻辑（不调原函数）**

```cpp
static int Det2(int x);
SYR_HOOK(L"game.exe", 0x2345, Det2, nullptr)
static int Det2(int x) { (void)x; return 1; }
```

**C. 任意地址牵引 / 直入某段**

```cpp
static long long Det3(long long x);
SYR_HOOK(L"game.exe", 0x3456, Det3, nullptr)
static long long Det3(long long x) {
  return ((long long (*)(long long))0x7FF612399000)(x);  // 直接调任意代码
}
```

**D. 运行时登记（无宏；地址运行期才知道）**

```cpp
SYR_PAYLOAD_WITH_INIT(MyInit)
static int MyInit() {
  uintptr_t addr = /* 扫描/解析得到 */ 0;
  if (!addr) return -1;
  return syr::g_api->hook_register(addr, (void*)&MyDetour, (void**)&MyOrig, "MyDetour");
}
```

**E. 特征码定位 + 钩取**

```cpp
SYR_PAYLOAD_WITH_INIT(ScanInit)
static int ScanInit() {
  uintptr_t hits[8] = {};
  int n = syr::g_api->scan(L"GameAssembly.dll", "48 8B 05 ?? ?? ?? ?? 48 85 C0", hits, 8);
  if (n <= 0) return -2;
  return syr::g_api->hook_register(hits[0], (void*)&Det, (void**)&Orig, "hit0");
}
```

**F. 堆上 RWX（JIT/生成代码）**

```cpp
uintptr_t hits[8] = {};
int n = syr::g_api->scan_rwx("48 8D 04 11 C3", hits, 8);  // lea rax,[rcx+rdx]; ret
if (n > 0) syr::g_api->hook_register(hits[0], (void*)&Det, (void**)&Orig, "jit");
```

### 7.6 能力速查（Api 表）

| 字段（顺序即 ABI） | 签名/语义 |
| --- | --- |
| `version` | int，当前 6 |
| `module_base(module)` | `uintptr_t(const wchar_t*)`；nullptr=主模块；0=未找到 |
| `hook_register(target, detour, &orig, name)` | 0=OK，2=ALREADY，4=CreateHook 失败，5=EnableHook 失败，-1=未初始化 |
| `hook_remove(target)` | 0=OK，1=不存在 |
| `write_mem(addr, buf, len)` | 0=OK，1=失败（改保护/写） |
| `scan(module, pattern, out, max)` | 命中数；-1 模块不存在；-2 模式空 |
| `install_section(module)` | 安装数；-1 头非法 |
| `log(fmt, ...)` | printf 风格；进 16KB 日志 |
| `read_mem(addr, buf, len)` | 0=OK，1=不可读（SEH 安全） |
| `alloc_mem(size, exec)` | 地址；0=失败；exec→RWX |
| `free_mem(addr)` | VirtualFree |
| `protect(addr, len, newprot)` | 旧保护；0=失败；exec 时刷 I-cache |
| `scan_rwx(pattern, out, max)` | 私有可执行页命中数；-2 模式空 |
| `cfg_status()` | 1=主模块开启 CF_INSTRUMENTED |
| `cfg_validate(addr, len)` | 0=通过/已放行（未开 CFG 或放行成功）；3=位图兜底写失败；1/2 只由 `cfg_bitmap_set` 返回，validate 内部吸收为 0 |
| `pe_sections(base, out, max)` | 段数；-1 头非法 |
| `pe_export(base, name)` | VA；0=未找到 |
| `scan_range(start, end, pattern, out, max)` | 命中数；-2 参数/模式错 |
| `cfg_bitmap_set(addr)` | 0=成功 1=未开 CFG 2=位图定位失败 3=写失败 |
| `cfg_bitmap_base()` | 位图基址；0=未开/定位失败 |

宏快捷方式（需 `g_api` 已就绪）：

```cpp
SYR_MEM_WRITE(addr, buf, len);   // 0/1
SYR_MEM_READ(addr, buf, len);    // 0/1
SYR_ALLOC(size, exec);           // addr
SYR_FREE(addr);
SYR_PROTECT(addr, len, PAGE_READONLY);  // 旧保护
```

### 7.7 RVA 获取

| 目标类型 | 方法 |
| --- | --- |
| 原生 EXE/DLL | IDA/Ghidra 静态地址 − 模块基址；`dumpbin /headers`；或 payload 内 `scan` 定位 |
| Unity IL2CPP | Il2CppDumper（`GameAssembly.dll` + `global-metadata.dat`）→ `dump.cs` + DummyDll；RVA 相对 `GameAssembly` |
| Unity Mono | dnSpy/ILSpy 读 IL；运行时 `mono_compile_method` 物化地址 → `hook_register`（见 `example/mono_resolve_recipe.cpp`） |
| 剥导出/手动映射 | `pe <base>` 拿可执行块 → `scanrange`/`export` |

**RVA 是每构建、每平台、每架构的**；不要跨游戏更新/跨平台复用。ASLR 由 `base+RVA` 解决。

### 7.8 验证 payload

1. `load` → 期望 `LOAD n`（n 等于 `.syhk64` 记录中成功安装数）。
2. `hooks` → 看到目标地址 + 名字。
3. `log` → `hook addr=... OK tramp=...`；失败会写 `ALREADY/NOT_EXECUTABLE/...`。
4. 触发目标行为，确认篡改/跳过/跳转符合预期。
5. 需要撤销：payload 里调 `hook_remove(addr)`；控制面没有 `hooks.remove`。

### 7.9 完整示例：从零写一个 payload 到验证

目标：在 `puppet64.exe` 上钩 `PuppetAdd`，让 `add 1 2` 从 `3` 变成 `103`。

**步骤 1：拿 RVA。** 启动靶机，banner 给出绝对地址；`RVA = ADD - BASE`。ASLR 每次不同，但 RVA 不变。

```
BASE=00007FF72D030000
ADD=00007FF72D031000
...
RVA = 0x1000
```

**步骤 2：写 payload（`D:\ctf\payloads\puppet_add.cpp`）。**

```cpp
#include "syringe.hpp"

#ifndef PUPPET_ADD_RVA
#define PUPPET_ADD_RVA 0
#endif

static long long (*OrigAdd)(long long, long long);
static long long D_Add(long long a, long long b);
SYR_HOOK(L"puppet64.exe", PUPPET_ADD_RVA, D_Add, &OrigAdd)
static long long D_Add(long long a, long long b) {
  return OrigAdd(a, b + 100);   // 第 2 参 +100
}

SYR_PAYLOAD()
```

**步骤 3：编译（RVA 用 `/D` 传入）。**

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cl /LD /O2 /MT /std:c++17 /source-charset:utf-8 /EHsc /W3 ^
   /I D:\ctf\ctf-syringe64\include ^
   /DPUPPET_ADD_RVA=0x1000 ^
   D:\ctf\payloads\puppet_add.cpp /Fe:D:\ctf\payloads\puppet_add.dll
```

**步骤 4：产物自检（三个都要过）。**

```bat
dumpbin /exports   D:\ctf\payloads\puppet_add.dll | findstr SyrPayloadInit   :: 必须有导出
dumpbin /headers   D:\ctf\payloads\puppet_add.dll | findstr syhk64           :: 必须有 .syhk64
dumpbin /dependents D:\ctf\payloads\puppet_add.dll                            :: 只应依赖 KERNEL32.dll
```

**步骤 5：注入 + 加载 + 验证。**

```powershell
$targetPid = (Get-Process puppet64).Id
& D:\ctf\ctf-syringe64\build\launcher64.exe --attach $targetPid D:\ctf\ctf-syringe64\build\syringe-tether.dll
& D:\ctf\ctf-syringe64\build\syrctl.exe $targetPid hello
& D:\ctf\ctf-syringe64\build\syrctl.exe $targetPid load D:\ctf\payloads\puppet_add.dll
& D:\ctf\ctf-syringe64\build\syrctl.exe $targetPid hooks
& D:\ctf\ctf-syringe64\build\syrctl.exe $targetPid log
```

**预期输出：**

```
LOAD 1
.
00007FF72D031000 D_Add
.
hook addr=00007FF72D031000 name=D_Add OK tramp=...
tether: payload D:\ctf\payloads\puppet_add.dll init -> 1
.
```

然后在靶机输入 `add 1 2` → `add=103`；`hooks` 能看到 `D_Add`；`log` 有 `OK tramp=...`。

**步骤 6：改错/迭代。** 目标更新或换构建后 RVA 会变，必须重新取 RVA 并重编；不要把 RVA 写死跨版本复用。

> 若 `LOAD 0` 且 `log` 出现 `hook addr=... NOT_EXECUTABLE`：RVA 错或模块未加载；若出现 `ALREADY`：同地址已装。

---

## 8. Unity / C# 场景

### 8.1 先判断后端

| 特征 | Mono | IL2CPP |
| --- | --- | --- |
| 文件 | `mono-2.0-bdwgc.dll`、`Managed/Assembly-CSharp.dll` | `GameAssembly.dll` + `*_Data/il2cpp_data/Metadata/global-metadata.dat` |
| 逻辑层 | IL（托管程序集） | native 代码 + metadata |
| 逆向 | dnSpy/ILSpy 读 IL | Il2CppDumper + IDA/Ghidra 读 native |
| 钩取 | 运行时解析/`mono_compile_method` → `hook_register` | RVA → `SYR_HOOK(L"GameAssembly.dll", rva, ...)` |

> 本机已安装 dnSpy MCP（headless，DSH 连接名 `dnspy`）：读 .NET/IL、`decompile_type`、`get_method_il`、`search_strings` 等直接可用；**它不负责注入/挂钩**，挂钩用本武器库。

### 8.2 IL2CPP 流程

1. Il2CppDumper 解析 `GameAssembly.dll` + `global-metadata.dat` → `dump.cs`、DummyDll。
2. 在 `dump.cs` 找到目标方法；记下其 RVA（或让 dumper 输出地址）。
3. payload：

```cpp
static long long (*OrigTarget)(void* self, int arg);
static long long DetTarget(void* self, int arg);
SYR_HOOK(L"GameAssembly.dll", 0x1A2B3C0, DetTarget, &OrigTarget)
static long long DetTarget(void* self, int arg) {
  return OrigTarget(self, arg);  // 观察/篡改
}
SYR_PAYLOAD()
```

4. `load` → `LOAD 1` → `hooks` 确认 → 触发行为。

> 泛型/共享方法可能多个 C# 方法共用一个 native 入口；钩它会同时影响这些方法。先小范围验证。

### 8.3 Mono 流程

1. dnSpy/ILSpy 看方法逻辑，确认类名/方法名/参数个数。
2. payload 内解析 mono API（`example/mono_resolve_recipe.cpp`）：

```cpp
uintptr_t addr = MonoResolve("Assembly-CSharp", "Game", "Player", "Die", 1);
if (!addr) return -1;
return syr::g_api->hook_register(addr, (void*)&DetDie, (void**)&OrigDie, "Player::Die");
```

3. `mono_compile_method` 会强制 JIT 并返回稳定入口；`hook_register` 对任意可执行地址同构。

### 8.4 IL 补丁

- Mono 程序集是明文 .NET DLL：定位方法体 IL → `write_mem` 等长改写；**先备份原字节**，避免不可逆。
- IL2CPP 没有可执行 IL；逻辑已是 native，只能改 native（`write_mem`）或钩取。
- 运行期补丁不持久；重启目标即恢复。

### 8.5 与 dnSpy MCP 的分工

| 任务 | 工具 |
| --- | --- |
| 看 C# 逻辑/类型/字符串/IL | dnSpy MCP（`dnspy` 连接） |
| 找 native RVA / 反汇编 | IDA/Ghidra + Il2CppDumper |
| 注入/挂钩/内存补丁/热加载 | 本武器库（launcher + tether + payload） |

---

## 9. 完整工作流与配方

### 9.1 定位 → 钩取 → 验证（原生）

```powershell
# 0) 记录目标 pid
$targetPid = (Get-Process game).Id

# 1) 注入 + 握手（重试）
& .\build\launcher64.exe --attach $targetPid (Resolve-Path .\build\syringe-tether.dll)
1..20 | % { $r = & .\build\syrctl.exe $targetPid hello 2>&1; if ($r -match 'syringe64 tether') { break }; Start-Sleep -Milliseconds 100 }

# 2) 找函数（示例：模块内特征码）
& .\build\syrctl.exe $targetPid modules            # 拿模块基址
& .\build\syrctl.exe $targetPid scan game.exe "48 89 5C 24 ?? 57"

# 3) 按 RVA 写 payload（或用运行时 scan + hook_register）
# 4) 编译 + load
& .\build\syrctl.exe $targetPid load D:\ctf\payloads\p1.dll
& .\build\syrctl.exe $targetPid hooks
& .\build\syrctl.exe $targetPid log

# 5) 行为验证 + 记录证据
```

### 9.2 内存补丁 + 还原

> 沿用 §9.1 的 `$targetPid`；下面只演示命令。

```powershell
$addr = (& .\build\syrctl.exe $targetPid alloc 64 1 | Select-Object -First 1).Trim()
& .\build\syrctl.exe $targetPid write $addr 90909090
& .\build\syrctl.exe $targetPid read $addr 4          # 90909090
# 原字节备份用 read 先取；还原用 write 写回
& .\build\syrctl.exe $targetPid free $addr
```

### 9.3 生成 stub 并执行

> 沿用 §9.1 的 `$targetPid`。

```powershell
$a = (& .\build\syrctl.exe $targetPid alloc 4096 1 | Select-Object -First 1).Trim()
# mov eax,0x5678; ret
& .\build\syrctl.exe $targetPid write $a B878560000C3
# 通过 payload 的 cfg_validate + cast 调用（或 C++ payload 内直接调用）
```

### 9.4 多 payload / 热加载

- 注入桥只注入一次；之后每次 `load` 一个新的宏 DLL 即可。
- 不同 DLL 的钩子互不影响；同地址重复登记返回 `ALREADY`。
- 同一路径重复 `load` 不会重新初始化；要重装换文件名或重启。
- 并发 `load` 不同 payload 会触发引擎钩子表的数据竞争（P2-7）；**串行 load** 更安全。

### 9.5 冻结/解冻（谨慎）

```powershell
# 仅当确定没有 payload/游戏线程在写日志时
& .\build\syrctl.exe $targetPid freeze
& .\build\syrctl.exe $targetPid load D:\ctf\payloads\p2.dll
& .\build\syrctl.exe $targetPid thaw
```

> 风险：`freeze` 盲挂所有线程；若被挂线程持有日志/CRT/loader 锁，后续 `load` 会永久阻塞，`thaw` 也不可达（管道 `gle=231`），只能杀目标。**默认不要 freeze**；MinHook 装钩自身会处理线程冻结。

---

## 10. 故障排查矩阵

| 症状 | 可能原因 | 处置 |
| --- | --- | --- |
| `open pipe failed gle=2/5/231` | tether 未注入 / 管道忙 / 权限 | 查 launcher 输出；重试；杀挂死客户端；确认同用户/位数 |
| `hello` 超时 | 目标冻结/卡死；tether 未起；管道被占 | 查目标是否被 freeze；杀客户端后重试；必要时重启目标 |
| `LOAD -1` | LoadLibrary 失败（路径/依赖/拦截） | 绝对路径、无空格；拷到游戏目录；看 launcher/目标错误；payload 自举 |
| `LOAD -100` | tether API 版本 < payload `SYR_API_MIN` | 更新 tether；或 payload 降低 `SYR_API_MIN` |
| `LOAD 0` 但预期有钩 | RVA=0 被跳过 / 模块未加载 / 重复登记 ALREADY | 查 `log` 的 `hook addr=` 行；`modules` 确认模块名；`hooks` 看是否已装 |
| `hook ... NOT_EXECUTABLE` | 目标地址不可执行/RVA 错/模块未加载导致 `0+RVA` | 校验 RVA 与模块；确保模块已加载；见 §11 P2-2 |
| `hook ... ALREADY` | 同地址已登记 | 正常；`hooks` 查看 |
| `ERR access`（read） | 地址不可读/跨未映射页/已 free | 用 `modules` 重取基址；分段读 |
| `ERR write` | 跨未映射页/保护改失败 | 分段写；确认地址已提交 |
| `ERR args` | 参数格式/长度/奇数 hex/空 | 查 §5；write ≤255B；read ≤2048 |
| `ERR scan` | 模式空/区间非法/模块不存在（带引号模块） | 用空格分隔 hex；模块名不加引号；`start<end` |
| `scan`/`scanrwx`/`scanrange` 客户端挂死 | 零命中帧缺陷（P1-1） | 杀客户端；改 HTTP；见 §11 |
| `freeze` 后 `load` 挂死、`hello` 也 `gle=231` | 盲挂持锁线程（P1-2） | 杀目标；避免 freeze；不要在有日志线程时 freeze |
| `syrctl` 模式命中 page±1 | 分参被空格重组截断（P1-3） | 整条命令一个 argv；或 HTTP |
| `create 冒烟 PASS` 但 Web 打不开 | 假绿（P1-4） | 单独验证 `hello` + `/`；看日志 |
| 目标崩溃于装钩后 | 钩在函数中间/签名错/覆盖关键指令 | 只钩入口；核对签名；先 `hooks`/`log` 验证单钩 |
| Web 打不开 | 端口占用/HTTP 线程未起/被 freeze | 查 `hello` 的 URL；`netstat`；避免 freeze；用管道 |
| 路径含空格 load 失败 | `sscanf` 截断 | 移到无空格路径 |
| `modules` 崩溃/异常 | >1024 模块越界（P2-5） | 避免在超大模块进程用 `modules`；用 `scan *`/已知基址 |

---

## 11. 已知缺陷与规避

以下为本仓库当前版本的**实测缺陷**（详见 `audit/REPORT.md`）。Agent 必须绕开。

### P1-1 零命中扫描挂死（管道）

- **触发**：`scan`/`scanrwx`/`scanrange` 通过 `syrctl` 执行且 0 命中。
- **机制**：tether 空结果只回 `"."`（`tether_main.cpp:181-187`），syrctl 只认 `"\n."`（`syrctl.cpp:35,51`）→ 永久阻塞；管道单连接期间其他客户端 `gle=231`。
- **规避**：扫描走 HTTP；或给 syrctl 包超时；挂死后杀客户端（管道会恢复）。

### P1-2 `freeze` 后日志类命令死锁

- **触发**：`freeze` 后执行会写日志的命令（`load`/`hook_register` 等），且被挂线程持有日志/CRT/loader 锁。
- **现象**：命令超时；随后 `hello`/`thaw` 均 `gle=231`；HTTP 线程也被挂起 → 无救援通道；只能杀目标。
- **规避**：不要 freeze；必须 freeze 时确保没有 payload/游戏线程在写日志，且 freeze 期间只做只读命令；优先用 MinHook 自身的线程冻结。

### P1-3 `syrctl` 多 token 模式截断（静默错答）

- **触发**：`syrctl <pid> scanrwx "48 8B ..."` / `scanrange <s> <e> "<pat>"`。
- **现象**：`scanrwx` 丢首字节命中 `page+1`；`scanrange` 把 end 当模式开头 → 0 命中。
- **规避**：整条命令作为一个 argv（`syrctl <pid> 'scanrwx "48 8B ..."'`）或 HTTP；`scan <module> "<pat>"` 因 arg2 恰为首 token 而可用。

### P1-4 `create` 冒烟假绿

- **触发**：`e2e_create.ps1` 的 Web 检查失败。
- **现象**：仍打印 `create smoke PASS` 并 exit 0；`build.ps1` 打印 OK。
- **规避**：不要只看 PASS；单独验证 `hello` 与 `/`；看日志中的 WebException。

### P2 级（影响正确性/稳定性，需留意）

| 编号 | 问题 | 规避 |
| --- | --- | --- |
| P2-1 | `thaw` 会恢复它未挂起的线程（over-resume） | 没有匹配的 `freeze` 就不要 `thaw`；不要重复 `thaw` |
| P2-2 | 模块未加载时按 `0+RVA` 尝试挂钩 | `modules` 确认模块；缺失模块的 `SYR_HOOK` 先删/条件化 |
| P2-3 | launcher 注入失败遗留孤儿 | 失败后检查并 `Stop-Process` |
| P2-4 | 文档编译命令缺 `/source-charset:utf-8` | 编译必加该开关 |
| P2-5 | `modules` >1024 模块越界 | 大进程避免 `modules`；用已知基址 |
| P2-6 | `LoadPayload` 10s 超时后路径字符串 UAF | 超大/慢 DLL 先拷本地盘；避免网络路径 |
| P2-7 | 日志/钩子表并发竞态 | 命令串行；不要并发 `load` 不同 payload |
| P2-8 | `SYR_API_MIN=3` 但存在 v6 字段 | 用 v6 字段时把 payload 的 `SYR_API_MIN` 提到 6（需改头文件） |

> 另：`hooks` 静态缓冲 4KB、`log` 16KB 追加式、`modules` 1024、`write` 255B/次、`read` 2048B/次。

---

## 12. Agent 操作检查清单

### 12.1 开始前

- [ ] 目标为 Windows x64，已授权，非受保护进程。
- [ ] 记下目标 PID；tether/payload 路径**无空格**、绝对路径。
- [ ] 准备超时包装（§4.3）；准备 HTTP 客户端（§4.4）。
- [ ] 确认 `launcher64.exe`/`syringe-tether.dll`/`syrctl.exe` 存在且是当前构建。

### 12.2 注入

- [ ] `launcher --attach <pid> <tether>`；退出 0。
- [ ] `syrctl <pid> hello` 重试至成功（30~60ms 就绪窗口）。
- [ ] 失败：查 `open pipe failed`/`remote LoadLibraryW returned NULL`；按 §6.3 处理。

### 12.3 加载 payload

- [ ] 编译：`/LD /O2 /MT /std:c++17 /source-charset:utf-8 /Iinclude`。
- [ ] `load <abs path>` → `LOAD n`；`n>0` 或明确为 0（无宏/已装）。
- [ ] `hooks` 数量/地址正确；`log` 无 `NOT_EXECUTABLE/ALREADY` 意外。
- [ ] 行为验证（目标函数调用结果）。

### 12.4 扫描/内存

- [ ] 扫描优先 HTTP；管道扫描必须包超时。
- [ ] 模式用空格分隔 hex；模块名不加引号。
- [ ] `write` 每次 ≤255B；`read` ≤2048B；地址 hex。
- [ ] 大块写分片；保留原字节备份。

### 12.5 结束

- [ ] `quit`（可选）；不提供 unload，必要时重启目标。
- [ ] 记录：pid、tether 路径、payload 路径、LOAD 返回、hooks、关键 log、行为对比。
- [ ] 清理临时进程/文件；不要留下孤儿目标。

---

## 13. 附录

### 13.1 协议帧

- 管道/HTTP 应答都以**单独一行 `.`** 结束。
- 扫描 0 命中是唯一例外（只回 `"."`，无前导换行）——客户端需按 §11 处理。
- `syrctl` 一次性：命令 = `argv[2..]` 用空格拼接 + `\n`；应答读到 `"\n."`；`ERR` 开头退出 1。
- `syrctl -` 交互：逐行读 stdin → 发送 → 读到 `"\n."` → 打印；`quit` 退出。**空行会挂**。
- HTTP：`GET /api/exec?c=<urlencoded>`；`GET /` 面板；`Content-Type: text/plain`；无鉴权，仅 127.0.0.1。
- 端口：`18700 + pid % 256`；绑定失败只写日志，`hello` 仍会广告 URL。

### 13.2 退出码 / 返回码

| 场景 | 值 |
| --- | --- |
| `syrctl` 成功 | 0 |
| `syrctl` 应答以 `ERR` 开头 / 管道打开失败 | 1 |
| `syrctl` 参数不足 | 2 |
| `hook_register` | 0 OK / 2 ALREADY / 4 CreateHook 失败 / 5 EnableHook 失败 / -1 未初始化 |
| `hook_remove` | 0 OK / 1 不存在 |
| `LOAD` | n=安装数 / 0 无钩子或已装 / -1 加载失败 / -100 API 版本低 |
| `cfgset` / `cfg_bitmap_set` | 0 成功 / 1 未开 CFG / 2 位图定位失败 / 3 写失败 |
| `install_section` | 安装数 / -1 头非法 |
| `scan*` | 命中数 / -1 模块不存在 / -2 参数或模式错 |
| `read_mem` / `write_mem` | 0 OK / 1 失败 |
| `protect` | 旧保护 / 0 失败 |
| `pe_sections` | 段数 / -1 头非法 |

### 13.3 文件布局

```
ctf-syringe64\
├─ build\                    # 产物（launcher/tether/syrctl/puppet/selftest/payload）
├─ include\syringe.hpp       # payload 唯一头（宏 + Api 表）
├─ src\core\                 # MinHook 薄封装 + Api 表
├─ src\tether\               # 管道/HTTP 控制面 + 热加载 + freeze
├─ src\launcher\             # 注入壳
├─ src\ctl\                  # syrctl
├─ test\                     # puppet64 / selftest / e2e
├─ example\                  # payload 模板（含 WCE 自举、mono 解析配方）
├─ vendor\minhook\           # MinHook（BSD-2，只读）
├─ audit\REPORT.md           # 全量审计报告（P1/P2 证据）
└─ AGENT-MANUAL.md           # 本手册
```

### 13.4 安全边界

- 仅面向**本地、授权**的 CTF 目标；不含网络攻击能力。
- 控制面只绑 `127.0.0.1`；管道是本机命名对象；无鉴权/无 Origin 校验（DESIGN 有，代码未实现）——不要暴露到网络。
- payload 在目标进程内运行，崩溃会带走目标；先在副本/靶机验证。
- 不处理内核反作弊/受保护进程；遇到请放弃或换环境。
- 修改目标文件/内存前确认授权与可逆性；保留原字节/原文件。

### 13.5 与仓库其它文档的关系

| 文档 | 内容 |
| --- | --- |
| `README.md` | 速览/架构/命令表 |
| `MANUAL.md` | 使用说明书（含故障排除） |
| `DESIGN.md` | v1 设计稿（注意与实现有漂移） |
| `DESIGN-UNITY.md` | RWX/托管策略 |
| `audit/REPORT.md` | 全量审计：测试矩阵、P1/P2/P3、证据日志 |
| **`AGENT-MANUAL.md`** | 本手册：Agent 可执行流程 + 安全红线 + 配方 |

---

> 最后更新：与 `audit/REPORT.md` 同批次（tether v6 / MinHook）。若代码更新，先重跑 `build.ps1`、`selftest.exe`、`test\e2e.ps1`，并复核 §11 的缺陷是否已修复。
