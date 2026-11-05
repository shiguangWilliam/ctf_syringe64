# ctf-syringe64 设计文档

> 状态：设计稿 v1（仅覆盖通用 64-bit / ASLR / 晚注入部分；C#/Unity 的 JIT/CFG 专项见 §10，后续单独立项）
> 参考前身：`D:\ra3\ra3-preinject-syringe`（32 位、基址 0x400000、无 ASLR、preinject 前注入）

## 0. 命名与定位

- 项目名：`ctf-syringe64`（工作代号 syringe64）。
- 一句话：面向未知 Windows 游戏客户端的**通用 64 位注入与挂钩武器库**——启动壳把一根常驻「牵引 DLL」送进目标进程，牵引对进程内提供 **RWX 写 + LoadLibrary 追加**两项原子能力，对外通过本地控制面（Web UI / 可选 in-game overlay）接受操作员指令，配合 RVA 化的钩子登记段在 ASLR 下完成动态地址解析与 trampoline 安装。
- 用途边界：CTF 赛制下对**本地游戏客户端**做逆向辅助与成就触发（内存修改、逻辑 patch、本地封包观测）。不含对服务器基础设施的攻击能力，不内置网络攻击载荷。

## 1. 为什么不能照搬 preinject

preinject-syringe 的四个前提在 CTF 目标上逐一失效：

| 前提 | RA3 1.12 | CTF 目标（预期） | 后果 |
| --- | --- | --- | --- |
| 位数 | 32 位 | 64 位 | 登记记录、trampoline 生成器、`E8/E9` 位移、偷指令反汇编全要重写 |
| 基址 | 固定 0x400000 | ASLR（高熵，EXE+DLL 全部随机） | 写死 VA 的 `HookDecl` 失效，必须在进程内按模块基址 + RVA 解析 |
| 注入时机 | 入口 int3 冻结期 preinject | 反作弊/完整性校验/启动器包裹下冻结窗口不可靠 | 需要**晚注入 + 常驻牵引**模式 |
| 目标形态 | 原生 C++ | 可能 Unity（IL2CPP / Mono）、可能 CFG 开启 | 偷指令长度、间接调用保护、GC 线程都引入新约束（§10） |

因此架构从「一次性 preinject」改为「**常驻牵引 + 外部驱动**」：

```
┌─────────────┐  控制面 (本地 HTTP/WS 或 named pipe)   ┌──────────────────────────┐
│  syringe-ui │ ────────────────────────────────────▶ │  目标进程                 │
│ (Web UI)    │ ◀──────────────────────────────────── │ ┌──────────────────────┐ │
└─────────────┘            事件/日志流                 │ │ 牵引 DLL (tether)    │ │
                                                       │ │  · RPC 分发线程       │ │
      │  远程 LoadLibraryW / 手动映射                    │ │  · RWX 写原语         │ │
      ▼                                               │ │  · 模块表/RVA 解析     │ │
┌─────────────┐                                        │ │  · 钩子引擎(继承)     │ │
│ launcher64  │── 创建/附着 ─────────────────────────▶ │ └──────────────────────┘ │
└─────────────┘                                        │   ▲ 追加: payload DLL ×N  │
                                                       │   └── 各自带 .syhks64 登记 │
                                                       └──────────────────────────┘
```

## 2. 组件划分

| 组件 | 产物 | 职责 |
| --- | --- | --- |
| `launcher64` | exe | 定位/创建/附着目标进程，把牵引 DLL 送进去（§4），之后退场；不承担安装 |
| `tether`（牵引） | dll，最小面 | 常驻：控制面服务、进程内写原语、模块枚举/RVA 解析、`LoadLibrary` 追加、钩子引擎宿主（§5） |
| `syringe-core` | 静态库 | 64 位 trampoline 生成器、`.syhks64` 登记/安装/卸载（从 ra3 项目移植重写，§6） |
| `syringe-ui` | 本地 Web 服务 + 浏览器页面 | 操作员 UI（§7） |
| payload 模板 | dll ×N | 赛场按题目写，宏登记钩子（RVA 形式），由牵引追加进目标 |

依赖方向：`tether`、payload → `syringe-core`；`syringe-ui` 只经控制面协议与 `tether` 交互。

## 3. 目标环境假设

- Windows 10/11 x64，游戏客户端为 64 位 PE（native C++ 或 Unity，Mono/IL2CPP 均可能）。
- 进程可能由启动器拉起、带完整性校验或轻量反作弊（假设为用户态、无内核驱动对抗；若出现内核对抗则超出本项目范围）。
- 注入时机不可控：既支持「创建即注入」（复刻 preinject 的入口冻结），也必须支持「进程已在跑」的晚注入。
- 反调试/反 DLL 扫描强度未知：牵引面要小、行为要像普通运行库（§8）。

## 4. launcher64：投放牵引

按优先级三种模式，全部实现：

1. **创建式**（首选，复用 ra3 经验）：`CreateProcessW(DEBUG_ONLY_THIS_PROCESS)` → 入口 `int3` → 远程 `LoadLibraryW(tether.dll)` →（可选立即安装冻结期钩子）→ `DebugActiveProcessStop` 摘调试器。64 位下入口点从 PE header 读，不再写死；若被调试检测命中则自动降级。
2. **附着式**：`OpenProcess` + 远程线程 `LoadLibraryW`。针对已经在跑的游戏。远程线程入口地址用 `GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW")`——各进程 kernel32 基址不同但函数 RVA 在同版本系统内一致，直接取本进程地址即可。
3. **手动映射**（兜底）：当目标监控 `LoadLibrary`（LdrRegisterDllNotification / 模块扫描）时，launcher 在本地完成 PE 加载器工作（映射节、处理重定位、解析导入、`TLS` 回调与 `DllMain` 经 shellcode 触发），把牵引以无模块形态植入。v1 实现「可选手动映射」，默认关。

降级链：创建式 → 附着式 → 手动映射，launcher 逐级尝试并把结果写日志。成功标志：牵引在目标内建立控制面并回报握手（§5.4）。

## 5. tether（牵引 DLL）：进程内的最小服务面

### 5.1 设计原则

- **小面常驻**：牵引本身不包含任何题目相关逻辑；赛场新需求一律「写新 payload DLL → 通过控制面热追加」，牵引与 launcher 不重编译。
- **两项原子能力**：`remote_write`（RWX 写）与 `load_payload`（LoadLibrary 追加）。其余能力（模块枚举、RVA 解析、钩子安装）都是围绕这两项的组合。
- **不主动做事**：牵引没有自己的定时器/轮询任务，只在 RPC 请求与 payload 调用下工作，避免与游戏主循环产生可观测的时序扰动。

### 5.2 RWX 写原语

```cpp
// syringe-core 暴露给 tether 的唯一写入口
enum WriteScope { Code, Data };
Status PiWrite(uintptr_t addr, const void* buf, size_t len, WriteScope scope);
```

- `VirtualProtect` 改 `PAGE_EXECUTE_READWRITE` → `memcpy` → 恢复原保护属性（记录并还原，不留下整段 RWX 的痕迹）。
- 写代码（Code）时默认对目标区间做 `FlushInstructionCache`。
- v2 增强项（设计预留，v1 不做）：多线程竞态防护——安装钩子时短暂 `SuspendThread` 全部非当前线程（快照 RIP 校验不在被覆盖区间才放行），或等价于 preinject「冻结期安装」的运行期版本。v1 依赖控制面操作员选择安静时机，风险写入日志。

### 5.3 LoadLibrary 追加

- 首选 `LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH)`，路径由 UI 传入（绝对路径）。
- 若目标对模块枚举敏感，提供 `LoadManualMapped` 路径：tether 内实现 `MemoryModuleLibrary`（与 launcher 手动映射共用同一 PE 加载器代码），映射结果登记进牵引自己的模块表，同样参与 §5.4 的 RVA 解析与 §6 的钩子安装。
- 每次追加记录：文件名、加载基址、时间、是否手动映射、导出的 `PiPayloadInit` 调用结果。

### 5.4 模块表与 RVA 解析（ASLR 核心）

进程内维护模块表，三来源合并：`EnumProcessModules`（经 `NtQueryInformationProcess`/psapi）、手动映射登记项、payload 自报。

```cpp
struct ModuleInfo { uintptr_t base; size_t size; std::wstring name; bool manual_mapped; };
uintptr_t ResolveRVA(const wchar_t* module, uint32_t rva);   // base + rva
```

- 所有对外 API（钩子登记、读写、符号查找）一律以 `(module_name, rva)` 寻址；写死 VA 的接口仅留作逃生口并打警告日志。
- 附加服务：`PiFindPattern(module, rva_range, pattern, mask)` —— CTF 下大量目标函数无符号，UI 里做特征码搜索（如 `48 89 5C 24 ?? 57 48 83 EC 20` + 通配），返回候选 RVA 列表由操作员确认。
- 基址缓存失效：控制面每次请求前校验模块仍在（避免游戏热重载/关卡切换后悬空）；`ResolveRVA` 命中已卸载模块时返回错误并清表项。

### 5.5 握手与生命周期

- 牵引 `DllMain` 只启动一个分发线程并建立控制面，不做任何其他事；`DLL_PROCESS_DETACH` 时若仍有活钩子，按 §6 卸载语义逐个摘除后再退出。
- 握手包：牵引版本、目标 PID、位数确认、模块表快照、能力位（是否有手动映射、是否有 CFG 绕过）。

## 6. syringe-core：64 位钩子引擎（移植重写）

从 ra3-preinject-syringe 移植，改动点：

1. **登记记录 `.syhks64`**：
   ```cpp
   struct HookDecl64 {
     uint32_t magic;            // 'P6HK'
     uint32_t module_name_rva;  // 指向目标模块名字符串（编译期 __builtin_ 不可用时由链接器符号表解决）
     uint32_t target_rva;       // 目标函数 RVA，运行时 base+rva
     uint32_t size;             // 0=自动反汇编凑 >=5（实际用 12~14 字节窗口，见下）
     const char* name;
     void* detour;
     void** original;
   };  // 48 字节（含对齐）
   ```
   宏 `PI_HOOK64(L"GameAssembly.dll", 0x1234560, MyFn, &orig)`；沿用 `PI_HOOK64_AT(...)` 锁长度版本与 `LENGTH_MISMATCH` 校验。
2. **trampoline 生成器 64 位化**：偷指令反汇编按 x64 重写（沿用/扩展原反汇编器，重点支持 `REX` 前缀、`rip` 相对寻址重定位——偷走 `48 8B 05 xx xx xx xx` 这类指令必须按新 trampoline 地址重算 displacement）；短 `jmp rel8` 扩成 `rel32`；detour 与 trampoline 距离可能超 ±2GB，cave 分配用 `VirtualAllocEx` 优先在目标模块 ±2GB 内找洞（`MEM_COMMIT` 反复尝试或枚举已映射空洞），找不到再退到任意地址并用 `mov rax, imm64; jmp rax` 的绝对跳转垫片。
3. **target 补丁**：`E9 rel32`（同 cave 近距）或 12 字节 `mov rax,imm64; jmp rax`（远距）。因此自动长度窗口从 32 位的 ≥5 提到 ≥5/≥12 两档。
4. **多 DLL 同地址链**：cave 链式容器语义整体保留（字典序 owner + 链节点 + 引用计数卸载），仅指针宽度与节点尺寸改 64 位。
5. **安装时机两种**：冻结期（launcher 创建式流程里，与 ra3 相同）与运行期（tether 收到 UI 指令后调用 `PreinjectInstallAll`，走 §5.2 写原语）。运行期安装前默认做全线程快照校验。
6. **CFG（Control Flow Guard）预案**：若目标进程开启 CFG（`PE->LOAD_CONFIG->GuardFlags`），间接调用校验位图会使 detour 指针非法。v1 方案：检测到 CFG 时钩子只允许**直接 patch 目标函数头部**（合法间接调用目标本身就在位图内，detour 走 trampoline 不受影响）；`SetProcessValidCallTargets` 留作 v2。完整 JIT/托管函数挂钩（Mono/IL2CPP 方法指针、tiered compilation 重编译）明确**不在 v1**，见 §10。

## 7. syringe-ui：外部控制面

### 7.1 形态选择

- **v1：本地 Web UI**（选定）。tether 内起一个仅绑定 `127.0.0.1` 的 HTTP + WebSocket 服务（嵌入轻量实现，不引大依赖；静态资源内嵌于 DLL 资源段）。浏览器打开即用。
- 理由：迭代快（改页面不用重编 DLL）、跨机调试方便（端口转发即可）、CTF 场景本地回环不产生外联。
- **v2 预留：in-game overlay**（ImGui on D3D11/12 swap chain hook）。注意 overlay 本身就是一次自举问题（要先钩 present 才能画 UI），放在 v2；v1 的 Web UI 已满足全部核心操作。

### 7.2 控制面协议（WebSocket JSON，全部请求带自增 id）

| 类别 | 消息 | 说明 |
| --- | --- | --- |
| 会话 | `hello` / `handshake` | UI 连上后收牵引握手包 |
| 模块 | `modules.list` / `modules.rescan` | 模块表；含 base/size/manual_mapped |
| 内存 | `mem.read{module,rva,len}` / `mem.write{module,rva,hex,scope}` | 读写原语（read 供 UI hex 查看） |
| 搜索 | `pattern.search{module,pattern,mask}` / `pattern.aob{bytes}` | 特征码/数组搜索，返回候选 RVA |
| 注入 | `payload.load{path,manual_map?}` / `payload.list` / `payload.unload{name}` | §5.3 追加 |
| 钩子 | `hooks.install{module,name?}` / `hooks.list` / `hooks.remove{name}` / `hooks.log` | 触发模块自带的 `.syhks64` 安装；日志流推送 |
| 进程 | `proc.info` / `proc.freeze{on/off}` | 全线程冻结/恢复（安装钩子辅助） |
| 事件 | `evt.log` / `evt.hook_trace` | 服务端推送：安装结果、payload 日志、可选钩子命中 trace |

安全边界：只绑回环、校验 `Origin` 头为本地页面、无任何远程可达配置项。这是 CTF 本地工具，不做多用户鉴权，但防的是「别的本地进程顺手连上」。

### 7.3 UI 页面（v1 范围）

1. Dashboard：握手信息、模块表、已加载 payload、钩子状态。
2. Memory：hex viewer + 写入（带 scope 选择与二次确认）。
3. Scanner：特征码搜索（结果可「标记为函数 → 生成 PI_HOOK64 代码片段」，方便赛场快速出 payload）。
4. Payloads：DLL 路径、加载/卸载、实时日志终端。

## 8. 隐蔽性与稳定性考量（面向反作弊扫描）

- 牵引不改名系统调用、不修改 PEB；模块名用无害普通名（可配置，默认 `d3d11ools.dll` 一类伪装暂不做——v1 用中性名 `syringe-tether.dll`，伪装名留配置项）。
- 手动映射路径保证 `LoadLibrary` 完全不出现，模块链表无痕；代价是不出现在模块表里，需依赖牵引自报（§5.4 已覆盖）。
- 控制面线程优先级 `THREAD_PRIORITY_LOWEST`，RPC 处理避免长持锁。
- 所有写操作留 undo 记录（原字节 + 原保护属性），UI 一键「全部还原」。

## 9. 里程碑

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| M1 | syringe-core 64 位移植：`.syhks64`、trampoline 生成器、cave 链 | 在自研 64 位 puppet（复刻 ra3 的 mid_puppet 思路）上冻结期安装通过，含 rip 相对指令与跨 2GB 用垫片的用例 |
| M2 | launcher64 三模式投放 + 附着式晚注入 + 牵引握手 | puppet 先跑 5 秒再附着，安装钩子成功且游戏线程无崩溃 |
| M3 | 控制面 + Web UI（模块表/读写/搜索/payload 追加） | 浏览器完成「搜索特征码 → 写内存 → 热加载 payload」全流程 |
| M4 | 手动映射路径 + 卸载/还原 + 日志体系 | LoadLibrary 被监控的模拟用例通过 |
| M5（后置） | C#/Unity 专项（§10）单独立项 | — |

## 10. C#/Unity 专项

已单独立项，完整设计见 [DESIGN-UNITY.md](DESIGN-UNITY.md)（后端探测、IL2CPP methodPointer 版本探测、Mono 编译钩 + IL 补丁模板、CRT 堆工具、CFG 对策与 `.syu64` 延迟安装队列）。

## 11. 仓库结构（规划）

```
ctf-syringe64/
  DESIGN.md            # 本文档
  build.ps1
  include/syringe.hpp  # 对 payload 作者的公共头（宏 + 类型）
  src/core/            # trampoline、登记段扫描、安装/卸载（M1）
  src/tether/          # 牵引：RPC 分发、控制面、写原语、模块表（M2/M3）
  src/launcher/        # launcher64（M2）
  src/ui/              # Web UI 静态资源 + 内嵌（M3）
  test/                # puppet64、selftest、e2e 脚本
  example/             # payload 范例（PI_HOOK64 用法）
```

— 以上为 v1 设计。实现从 M1（puppet64 + 64 位 trampoline）起步。
