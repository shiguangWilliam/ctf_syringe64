# ctf-syringe64 二期设计：Unity / C# 专项（Mono · IL2CPP · IL2 · CRT · CFG）

> 状态：设计稿 v1。前置：一期已交付（MinHook 引擎 + 牵引 + 宏约定 + Api 表 v3，见 [DESIGN.md](DESIGN.md) / [README.md](README.md)）。
> 本期不改注入器形态：**tether / launcher 一次编译的约束继续成立**，全部新能力以「Api 表尾部追加 + 子表指针」方式提供，旧 payload 不受影响。

## 0. 背景与目标

CTF 目标若是 Unity 客户端，钩子面从「native 函数入口」扩展为四层：

| 层 | 内容 | 一期能否覆盖 |
| --- | --- | --- |
| L1 native 引擎层 | UnityPlayer.dll / GameAssembly.dll / mono-2.0-bdwgc.dll 的原生函数 | ✅ 已覆盖（RVA + 特征码 + MinHook） |
| L2 托管方法层（IL2CPP） | C# 方法已被 AOT 成 native 代码 | ⚠️ 机制可用，但「按 类.方法名 定位」无封装 |
| L3 托管方法层（Mono JIT） | C# 方法运行时才编译成机器码，地址动态且会重编译 | ❌ 需要专门设计 |
| L4 IL 层 | 直接改托管方法的 IL 字节码（跳过逻辑/常量篡改） | ❌ 需要专门设计 |
| 横切：CRT/CFG | CRT 分配器钩子；CFG 对函数指针调用的影响 | ❌ 需要专门设计 |

目标：给出 L2–L4 与横切项的 API/宏设计、实现路径、验证方案与里程碑。

## 1. 后端探测（一切的前置）

`tether` 注入后（或 payload 首次调用 unity Api 时）执行一次探测，结果缓存并广播：

```
UnityBackend DetectBackend():
  1. EnumProcessModules 查找:
     - "GameAssembly.dll"           -> IL2CPP
     - "mono-2.0-bdwgc.dll"         -> Mono (含 "EmbedMediaPlayer.dll"/"MonoPosix" 佐证)
     - "UnityPlayer.dll"            -> 记录基址(两后端均可能存在)
     - "kleptogamedebug"/其它发行壳  -> 仅记录
  2. 对 IL2CPP: 验证导出 il2cpp_domain_get / il2cpp_init 存在;
     若导出被剥(部分加固壳), 置 BACKEND_IL2CPP_STRIPPED, 走 §2.4 兜底
  3. 返回: IL2CPP | IL2CPP_STRIPPED | MONO | NONE
```

Payload 侧接口：`api->unity->backend()` 与 `api->unity->unity_player_base()`。

## 2. IL2CPP 后端（L2，优先级最高——现代 Unity CTF 客户端的主流）

### 2.1 核心机制

C# 方法在构建期已被编译为 `GameAssembly.dll` 内的普通 native 函数。**挂钩本身复用一期引擎**（MinHook patch 函数入口即可），本期要解决的是**定位**与**托管调用**两件事：

- 定位：`类.方法名 → MethodInfo* → methodPointer（native 地址）→ SYR_HOOK`。
- 托管调用：从 payload（native 线程）直接调用 C# 方法 / 构造 C# 对象与字符串。

### 2.2 运行时导出解析（首选路径）

从 `GameAssembly.dll` 解析函数表（GetProcAddress 优先，缺失的用签名扫描兜底——一期 `scan` 直接可用）：

```
il2cpp_domain_get / il2cpp_domain_get_assemblies / il2cpp_assembly_get_image
il2cpp_class_from_name / il2cpp_class_get_method_from_name
il2cpp_runtime_invoke / il2cpp_object_new / il2cpp_string_new / il2cpp_string_chars
il2cpp_thread_attach / il2cpp_thread_detach
il2cpp_method_get_name / il2cpp_class_get_name / il2cpp_class_get_namespace
```

### 2.3 methodPointer 的版本化结构探测

`il2cpp_class_get_method_from_name` 返回 `MethodInfo*`，其 `methodPointer` 字段偏移随 Unity 版本（2019–6000.x）变化。设计：

1. 维护已知版本偏移表（2019.4 / 2020.3 / 2021.3 / 2022.3 / 6000.x 各一档，以 il2cpp 头文件历史为源）；
2. **自校验**：用 `il2cpp_runtime_class_init + il2cpp_resolve_icall` 或对一个已知无重载的静态方法取 `methodPointer`，反查该地址是否落在 GameAssembly 的 `.text` 内且起始字节像函数序言（`48 89 5C` / `55 48 8B EC` / `40 53`…），不匹配则轮询下一偏移；
3. 探测结果（`MethodInfo 布局版本`）写日志，`hooks` 命令可见。

### 2.4 导出被剥的兜底（U4，最后做）

解析 `global-metadata.dat`（`Data/Managed/Metadata/`，内存中由 `il2cpp_init` 映射）：
- 定位 `Il2CppCodeRegistration / Il2CppMetadataRegistration`（签名扫描）；
- 由 method token → `methodPointers[]` 索引。
仅做只读解析，不修改 metadata。**明确为兜底位**：绝大多数 Unity Windows 构建导出未剥。

### 2.5 宏 API

```cpp
// payload 作者视角: 与 SYR_HOOK 同形, 只是目标从 (模块,RVA) 变为 (程序集,命名空间,类,方法)
static void (*OrigAddScore)(void* self, int delta);
static void D_AddScore(void* self, int delta);
SYR_IL2CPP_HOOK("Assembly-CSharp", "", "ScoreManager", "AddScore", D_AddScore, &OrigAddScore)
static void D_AddScore(void* self, int delta) { OrigAddScore(self, delta * 100); }  // 参数篡改照旧
```

- 登记段扩展：`.syu64`（新 magic `'SYU6'`），记录含程序集/命名空间/类/方法四个字符串指针 + detour + original + `argc`（用于消除重载歧义）+ flags（static/instance）。
- 安装语义：payload `SyrPayloadInit` 时若后端未就绪（游戏还在加载 GameAssembly），引擎将登记项挂入**延迟安装队列**，模块加载通知（`LdrRegisterDllNotification`）触发补装；避免时序踩空。这是与一期最大的行为差异，明确写入文档。

### 2.6 托管调用辅助（CTF 神器）

```cpp
// 从 native 直接调用任意 C# 方法 / 造对象 / 造字符串
void* UInvoke(void* method_info, void** args);        // = il2cpp_runtime_invoke 封装(自动 thread_attach)
void* UNew(const char* ns, const char* cls);           // il2cpp_object_new
void* UNewStr(const char16_t* s);                      // il2cpp_string_new
```

用途示例：payload 钩到敏感函数后，直接调游戏自己的 `AchievementManager.Unlock(id)` 触发成就链。

## 3. Mono 后端（L3 + L4，复杂度最高）

### 3.1 核心难点

1. 托管方法运行时才 JIT，地址在 `mono-2.0-bdwgc.dll` 之外的 RWX 代码堆上；
2. 方法入口首次调用前是 **precode stub**（`jmp [rip+disp]` → JIT 编译 helper），直接钩 stub 会被 JIT 重写覆盖；
3. Mono JIT 重编译（generic sharing / delegate 包装）可能换地址；
4. native 线程调 mono API 前必须 `mono_thread_attach(root_domain)`，否则 GC 崩溃。

### 3.2 解析表

```
mono_get_root_domain / mono_thread_attach
mono_domain_assembly_open / mono_assembly_get_image
mono_class_from_name / mono_class_get_method_from_name
mono_compile_method          <- 强制立即 JIT, 返回稳定 native 入口
mono_runtime_invoke / mono_object_new / mono_string_new
mono_method_get_header / mono_image_loaded
```

### 3.3 挂钩策略（三级）

| 级 | 策略 | 适用 |
| --- | --- | --- |
| M1 | `mono_compile_method(m)` 强制 JIT → 对返回地址跑 MinHook | 默认。编译产物地址此后稳定（Mono 无 CoreCLR 式分层重编译） |
| M2 | 钩 mono 运行时自身导出（`mono_runtime_invoke` 等）做全局观测 | 侦察/盲测问号成就 |
| M3 | IL 补丁（§3.4，不碰机器码） | 跳过逻辑/改常量，最抗重编译 |

M1 细节：
- 拿 native 地址后**先读首字节**，若仍是 precode（`E9/FF 25` 指向 mono 内部 helper）则先通过 `mono_runtime_invoke(m, nullptr, nullptr, nullptr)` 温和触发一次再钩；
- detour 回调内如果再进入托管世界（调 mono API），入口先 `mono_thread_attach`（引擎提供 per-thread 自动 attach 的辅助导出 `UMonoEnsureThread()`，用 TLS 标记防重入）。

### 3.4 IL 补丁层（L4）

不碰机器码，直接改**已加载程序集镜像内的方法体 IL 字节**（Mono 的 image 在托管堆/私有内存，`mono_image_loaded("Assembly-CSharp")` 定位）。

提供一组「安全 IL 模板」（按返回类型生成最小方法体，替换原 IL 体，不改 header 的 code_size 语义——模板按原长度 NOP 填充）：

| 模板 | IL 序列 | 效果 |
| --- | --- | --- |
| `SKIP_RET_VOID` | `ret` + NOP 填充 | 跳过整个方法 |
| `SKIP_RET_I4(n)` | `ldc.i4 n; ret` + NOP | 跳过并返回常量 |
| `SKIP_RET_I8/F/REF` | `ldc.i8`/`ldsfld`… + `ret` | 同上各类型 |
| `PATCH_STLOC/LDC` | 指定偏移处替换 `ldc.*` 操作数 | 常量篡改（如 `if (score < 9999)`） |

宏面：

```cpp
SYR_MONO_HOOK("Assembly-CSharp", "ScoreManager", "AddScore", D_AddScore, &OrigAddScore)  // M1 机器码钩
SYR_MONO_IL_SKIP("Assembly-CSharp", "Game.Checkpoint", "Die")                            // 模板: 直接 ret
SYR_MONO_IL_CONST("Assembly-CSharp", "Game.Rules", "MaxHp", 9999)                         // 常量篡改(静态字段初始化或ldc)
```

IL 层风险控制：所有模板只做「体长不变」的改写；方法体定位由 `mono_class_get_method_from_name → mono_method_get_header` 取 RVA，不猜偏移。

### 3.5 Mono 宏登记

复用 `.syu64` 段，flags 区分 IL2CPP/Mono/IL 模式，字段为（程序集, 命名空间, 类, 方法, argc, detour, original）。

## 4. CRT / 堆（横切）

1. **payload CRT 策略（沿用并明确）**：payload 一律 `/MT` 静态 CRT；tether `LOAD_WITH_ALTERED_SEARCH_PATH` 已保证目标缺 ucrtbase 时不炸。
2. **CRT 分配器钩子（堆观测/篡改）**：
   - 目标模块（含 IL2CPP 的 native 侧）分配走 `ucrtbase!malloc / operator new`；提供 `SYR_HOOK` 样例模板（特征码定位 `malloc`，一期能力即可）；
   - 引擎新增 `heap_snapshot(cb)`：`HeapWalk` 目标进程默认堆，导出 (ptr,size) 流供 CTF 快速定位 game state（比全模块特征码扫描快 1–2 个量级）。
3. IL2CPP/Mono 的**托管对象**不在 CRT 堆上（BOEHM/IL2CPP GC 自管理）——文档明确边界：托管对象定位走 §2.6/§3.2 的反射式查找，不走 CRT。

## 5. CFG（横切）

### 5.1 影响面判定（重要：默认路径不受影响）

- **MinHook 函数头 patch 不受 CFG 影响**：CFG 只校验「间接调用的目标地址」是否在进程位图；我们 patch 的是目标函数自身（合法间接调用目标，天然在位图）。一期全部 SYR_HOOK 在 CFG 进程下可用。
- 受影响的只有两个新场景：
  1. **任意地址牵引**（cast 调用）：目标地址必须在位图，否则 `STATUS_STACK_BUFFER_OVERRUN` 终止；
  2. **动态生成代码 stub**（`alloc_mem(…, exec)` 后 cast 调用，selftest 已演示的能力）：RWX 页不在位图。

### 5.2 对策：`cfg_validate(addr)`

```
Api 追加: int cfg_validate(uintptr_t addr, size_t len)
  = SetProcessValidCallTargets(GetCurrentProcess(), 当前进程句柄, 1, &{addr,len}, &ok)
```

- 引擎在以下路径**自动调用**：`hook_register` 检测到目标进程 `PE->LOAD_CONFIG->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED` 且登记的 detour 需要 cast 调用 stub 时；
- payload 手动路径：`SYR_CFG_VALIDATE(addr)`；
- 另提供 `cfg_status()` 返回（instrumented? export-suppressed? guard-dispatch 位图粒度），`hello`/`modules` 命令透出，操作员可判断。

### 5.3 guard dispatch 侦察钩（可选工具）

对 `__guard_dispatch_icall_fptr`（ntdll!LdrpDispatchUserCallTarget 或 PE 导出的 guard thunk）挂钩，可观测全部受保护间接调用 `(目标, 调用点)`——CTF 盲测问号成就时的行为侧信道。默认不装，宏 `SYR_CFG_TRACE()` 显式启用。

### 5.4 现实预期

Unity Windows 构建（Mono 与 IL2CPP）默认**不开** `/guard:cf`；本期 CFG 工作主要服务「游戏壳/加固/自研 native 模块开了 CFG」的场景。检测优先、按需启用。

## 6. Api 表与版本契约（保持注入器不变量的关键）

主 `Api` 只**尾部追加**一个子表指针（v4，`SYR_API_MIN` 保持 3，旧 payload 不受影响）：

```cpp
struct UnityApi {
  int version;                      // UNITY_API_MIN = 1
  int (*backend)(void);             // 0=NONE 1=IL2CPP 2=MONO 3=IL2CPP_STRIPPED
  uintptr_t (*unity_player_base)(void);
  // IL2CPP
  void*  (*il2cpp_class_from_name)(const char* asm_name, const char* ns, const char* cls);
  void*  (*il2cpp_method_from_name)(void* klass, const char* name, int argc);
  uintptr_t (*il2cpp_method_pointer)(void* method);        // 含版本化偏移探测
  // Mono
  void*  (*mono_class_from_name)(const char* image, const char* ns, const char* cls);
  void*  (*mono_method_from_name)(void* klass, const char* name, int argc);
  uintptr_t (*mono_compile)(void* method);                 // M1: 强制 JIT 返回地址
  int    (*mono_ensure_thread)(void);                      // 自动 thread_attach(TLS 防重入)
  // 共用托管调用
  void*  (*invoke)(void* method, void** args);             // runtime_invoke 封装
  void*  (*new_str)(const char16_t* utf16);
  int    (*il_patch)(void* method, int tmpl, int64_t imm); // §3.4 模板
  // CFG
  int    (*cfg_status)(void);
  int    (*cfg_validate)(uintptr_t addr, size_t len);
  // 堆
  int    (*heap_walk)(int (*cb)(uintptr_t, size_t, void*), void* ctx);
};
// 主表尾部追加: const UnityApi* (*unity)(void);
```

宏 `SYR_IL2CPP_HOOK / SYR_MONO_HOOK / SYR_MONO_IL_SKIP / SYR_MONO_IL_CONST` 只登记 `.syu64`，安装统一由引擎在 `install_section` 时按后端分发（含 §2.5 延迟队列）。

## 7. 风险与未决

| 风险 | 缓解 |
| --- | --- |
| `methodPointer` 偏移探测失败（魔改 il2cpp） | 轮询+反查校验；最终兜底 metadata 解析（U4） |
| Mono 方法 JIT 后仍被重编译（罕见 generic 场景） | M3 IL 补丁层替代；登记时给 flags 选择 |
| 延迟安装窗口内目标已被调用过（补钩错过首次调用） | 文档明示：问号成就盲测建议 M2 观测钩先行 |
| IL 模板破坏紧致异常表/调试信息 | 模板只做等长改写；写入前后 `read_mem` 快照可回滚 |
| CFG 位图修改被反作弊盯上 | `cfg_status` 先检；未开 CFG 的主流场景零触碰 |
| 托管调用触发游戏自身校验（服务器校验上报值） | 不属于本层问题；网络层留待三期 |

## 8. 里程碑

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| U1 | 后端探测 + IL2CppApi 解析（含 methodPointer 版本探测）+ `SYR_IL2CPP_HOOK` + `invoke` | 在真实 Unity 2022.3 IL2CPP 空构建上：定位 `Awake/Update`，参数篡改 + IL 跳过各 1 例 |
| U2 | Mono 全链路：解析表 + thread attach + M1 编译钩 + M2 观测钩 + `SYR_MONO_HOOK` | 在自建 mono-puppet（宿主 mono-2.0-bdwgc 的 64 位测试进程）上全部通过 |
| U3 | IL 补丁层 4 模板 + `SYR_MONO_IL_SKIP/CONST` | mono-puppet：Die 跳过、MaxHp 常量改写、可回滚 |
| U4 | CFG（status/validate/trace）+ CRT 堆工具 + `.syu64` 延迟安装 | cfg-puppet（手工开 /guard:cf 的样例）+ heap snapshot 冒烟 |
| U5（兜底，可选） | 剥导出 IL2CPP 的 metadata 解析 | 魔改样例 |

测试基建：`test/mono_puppet/`（Native 宿主 mono 运行时加载自编译 C# 程序集）、真实 Unity 构建两份（Mono/IL2CPP）作 U1 手动 e2e（构建产物不入库，README 记录步骤）。

— 以上为二期设计稿。确认后按 U1 → U2 → U3 → U4 顺序实施，每阶段沿用一期 selftest + e2e + 负例的验收格式。
