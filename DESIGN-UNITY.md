# ctf-syringe64 二期设计（定稿 v3）：RWX 通用注入面，不解析托管运行时

> 状态：定稿。取代 v1/v2 草稿。
> 原则：**注入器只提供「对任意可执行代码（模块 .text 或堆上 RWX）的钩取/调用/篡改/插跳板」通用能力，
> 不内置 mono/IL/IL2CPP 的主动解析**——这些与客户端、编译器、产物形态高度耦合，属于 payload 侧配方。

## 0. 决策记录

| 议题 | 决策 | 理由 |
| --- | --- | --- |
| IL2CPP 方法定位 | **引擎不做** | 全部是 GameAssembly.dll .text 里的 sub_，IDA+Il2CppDumper 离线拿 RVA，一期 `SYR_HOOK` 终局 |
| Mono 方法名→地址解析 | **引擎不做**，payload 配方 | 与 mono 版本/GC/时序耦合；payload 自己 `GetProcAddress("mono-2.0-bdwgc.dll", ...)` 即可，引擎代劳违反分层原则 |
| IL 补丁 | **引擎不做**，payload 配方 | 同上；程序集是明文 .NET DLL，方法体定位/改写都可在 payload 里用 Win32 + metadata 完成 |
| 堆上 RWX 代码（JIT 产物/运行期生成 stub） | **引擎做**，通用化 | 这正是「离线逆向拿不到地址」的通用形态；不问代码从哪来，只保证钩/调/写/扫四件事对其有效 |
| CFG | **引擎做**（status/validate） | 与运行时无关的 OS 层通用机制 |

## 1. 引擎侧能力（已实现于 Api v4，全部尾追加，`SYR_API_MIN` 不动）

对「堆上 RWX 可执行片段」的四件事与验证方式：

| 能力 | API | 状态 |
| --- | --- | --- |
| 钩取（入口 patch + MinHook 跳板） | `hook_register(任意地址)` | ✅ selftest「JIT 模拟」：RWX 页生成 `lea rax,[rcx+rdx];ret`，钩后参数篡改 3+4→107，解钩还原 7 |
| 调用（cast 执行任意地址） | 任意地址 cast（+`cfg_validate`） | ✅ selftest：RWX 页 `mov eax,0x5678;ret` 直接调用 |
| 篡改（RWX 页保护往返写） | `write_mem` / `read_mem` / `protect` | ✅ selftest：写-执行-还原闭环 |
| **定位**（不知道地址时） | `scan_rwx(pattern)` | ✅ selftest：全进程私有可执行页特征码扫描，两段生成代码均命中 |

`scan_rwx` 语义：遍历 `VirtualQuery`，只扫 `MEM_COMMIT + MEM_PRIVATE + 可执行保护` 的区域（JIT 代码堆、MinHook 跳板、游戏自己生成的 stub 都在此列），模式语法同 `scan`（`??` 通配）。这是「不解析 mono 也能找到 JIT 产物」的通用替代：分析侧（dnSpy/IDA/动态 dump）给出特征码，引擎负责在活进程里物化地址。

控制面对应命令：`scanrwx "<pattern>"`。

CFG（`cfg_status` / `cfg_validate(addr,len)`）：状态=主模块 `LOAD_CONFIG.GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED`；validate=未开 CFG 恒通过，已开则 best-effort `SetProcessValidCallTargets` 放行任意执行地址（供 cast 调用/生成 stub 使用；MinHook 函数头 patch 本就免疫 CFG）。

## 2. payload 侧配方（文档化，不进引擎）

- `example/mono_resolve_recipe.cpp`（随文档提供）：payload 内 `GetProcAddress` 解析
  `mono_get_root_domain / mono_thread_attach / mono_image_loaded / mono_class_from_name /
  mono_class_get_method_from_name / mono_compile_method`，把 `类.方法` 物化成地址后
  **交给引擎的 `hook_register`**——引擎自始至终不知道 mono 存在。
- IL2CPP：无需配方，Il2CppDumper→IDA→`SYR_HOOK(RVA)`。
- IL 补丁：payload 内解析程序集 PE + 方法表，改写用引擎 `write_mem`（等长改写，写入前后快照自管）。
- 钩 mono 运行时自身：`SYR_HOOK(L"mono-2.0-bdwgc.dll", RVA)`，一期能力。

## 3. 边界与已知项

- `scan_rwx` 只扫私有可执行页；若目标把 JIT 代码放共享节（罕见），用 `scan *`（全模块）或 `read_mem` 手动遍历补位；
- Mono detour 回调进托管世界前 `mono_thread_attach` 由 payload 配方自理（引擎无托管概念）；
- `cfg_validate` 的 `SetProcessValidCallTargets(NULL section)` 在部分老系统语义受限，失败写日志，操作员可对齐 16 字节粒度重试；
- 动态生成代码执行前建议 `cfg_validate`（未开 CFG 时为 no-op，无成本）。

## 4. 验收（已完成）

selftest 新增 12 项：JIT 模拟执行×2、`scan_rwx` 命中×2、RWX 钩取+参数篡改、解钩还原、`cfg_status/validate` 冒烟；e2e 维持全绿（一期链路不受影响）。
