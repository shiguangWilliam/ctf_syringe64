# ctf-syringe64 二期设计（修订版）：Unity / C# 专项

> 状态：设计稿 v2（按「IDA 在前、注入器只补必需缺口」的原则修订，取代 v1 的全面托管方案）。
> 前置：一期已交付（MinHook 引擎 + 牵引 + 宏约定 + Api v3，见 [DESIGN.md](DESIGN.md) / [README.md](README.md)）。
> 注入器「一次编译」不变量继续成立：新能力一律 Api 表尾部追加。

## 0. 设计原则（本修订的核心判断）

**工作流是「IDA/逆向在前，注入在后」**：先逆向突破拿到地址，再用一期任意地址注入。
因此二期只回答一个问题：*哪些东西在逆向产物里拿不到地址？* 只有这些才值得给注入器加能力。

| 东西 | 地址能否离线逆向获得 | 结论 |
| --- | --- | --- |
| IL2CPP 方法（含泛型实例） | ✅ 全部在 GameAssembly.dll .text，IDA+Il2CppDumper 出 RVA | **不加机制**，一期 `SYR_HOOK(模块,RVA)` 直接用 |
| IL2CPP delegate/虚表 | ✅ 数据段，IDA 可见 | 一期 `write_mem` 直接用 |
| mono-2.0-bdwgc.dll 自身 | ✅ 普通 PE 带导出 | 一期 `SYR_HOOK` 直接用（M2 观测钩也只是模板） |
| UnityPlayer.dll / dxgi / CRT | ✅ 普通 PE | 一期直接用 |
| **Mono 托管方法的 JIT 产物** | ❌ **运行期生成的堆上 RWX，不在任何模块 .text**，IDA 打开磁盘文件看不到 | **唯一必需的注入器新增：运行时地址解析** |
| Mono 托管方法体（IL 字节） | ⚠️ 程序集是磁盘文件（dnSpy 可读），但**方法体在进程内的内存位置**需运行时 metadata 定位 | 可选新增：IL 定位+模板（抗重编译的替代层） |

据此砍掉 v1 设计中的：IL2CPP 导出解析/`.syu64` 延迟队列/methodPointer 版本探测（U1 整段降级为可选便利工具，见 §4）。

## 1. 后端探测（保留，成本极低）

```
backend(): IL2CPP | MONO | NONE
  GameAssembly.dll 存在 -> IL2CPP（流程回到一期: IDA + SYR_HOOK RVA, 本设计不涉）
  mono-2.0-bdwgc.dll 存在 -> MONO（进入 §2/§3）
```

## 2. Mono：运行时地址解析服务（唯一必需项）

### 2.1 问题定义

Assembly-CSharp 的方法体 JIT 后地址 = f(进程, ASLR, 分配时序)，**无法从任何磁盘文件推出**。
逆向侧能拿到的是：dnSpy 读出的 `命名空间.类.方法` 名字（托管程序集是明文 .NET DLL）。
注入器要补的就是 `名字 → 运行时地址` 这一跳。

### 2.2 实现：解析表 + 两个函数

从 mono-2.0-bdwgc.dll（普通导出 DLL）GetProcAddress：

```
mono_get_root_domain / mono_thread_attach        <- native 线程进托管世界的门票
mono_image_loaded / mono_class_from_name / mono_class_get_method_from_name
mono_compile_method                              <- 强制 JIT, 返回稳定 native 入口
```

新增引擎服务（Api 尾部追加的 `UnityApi` 子表）：

```cpp
// 名字 → 运行时机器码地址。addr=0 表示找不到该类/方法(日志给原因)。
uintptr_t (*mono_resolve)(const char* image, const char* ns,
                          const char* cls, const char* method, int argc);
int       (*mono_ensure_thread)(void);   // TLS 防重入的 thread_attach
```

### 2.3 payload 用法（全部一期宏，零新钩子机制）

```cpp
static void (*OrigDie)(void* self);
static void D_Die(void* self) { /* 跳过: 不调 OrigDie */ }

extern "C" __declspec(dllexport) int __cdecl SyrPayloadInit(const syr::Api* api) {
  uintptr_t die = api->unity->mono_resolve(
      "Assembly-CSharp", "Game", "Player", "Die", 1);
  if (!die) return -1;
  return api->hook_register(die, (void*)&D_Die, (void**)&OrigDie, "Player::Die");
}
```

机制细节：
- `mono_compile_method` 强制 JIT，返回地址此后稳定（Mono 无分层重编译）；
- 兜底：若返回的入口仍是 precode stub（`FF 25` 指向 mono 内部 helper），引擎先 `mono_runtime_invoke` 温和触发一次再取地址——封装在 `mono_resolve` 内部，payload 无感；
- detour 回调若要调 mono API，先 `mono_ensure_thread()`（GC 安全）。

### 2.4 为什么钩 mono 自身的函数不需要新设计

mono-2.0-bdwgc.dll 是带导出的普通 PE：`SYR_HOOK(L"mono-2.0-bdwgc.dll", RVA)` 或
`api->module_base + GetProcAddress` 即可。例如全局观测托管调用的
`mono_runtime_invoke` 钩，就是普通一期钩子——文档只提供 payload 模板（example/），不进引擎。

## 3. Mono：IL 定位与补丁层（可选，第二优先级）

### 3.1 定位与价值

- 程序集（Assembly-CSharp.dll）在进程内按 PE 映像加载，**方法体 IL 是内存中的数据**；
- 定位链：`mono_image_loaded → mono_class_from_name → mono_class_get_method_from_name → mono_method_get_header` 拿方法体 RVA（不猜偏移）；
- 价值：改 IL 不碰机器码，**天然抗 JIT 重编译**，且「跳过逻辑」在 IL 层是 2 字节（`ret`）的事。

### 3.2 安全 IL 模板（等长改写，可回滚）

| 模板 | IL | 效果 |
| --- | --- | --- |
| `SKIP_RET_VOID` | `2A` + NOP 填充原长 | 整个方法变 no-op |
| `SKIP_RET_I4(imm)` | `20 <i32>` / `8 * <i8>` + `2A` + 填充 | 跳过并返回常量 |
| `CONST_PATCH(off,imm)` | 指定偏移替换 `ldc.*` 操作数 | 常量篡改 |

```cpp
// Api: int (*il_patch)(const char* image, ns, cls, method, int argc,
//                       int template, int64_t imm);   // 写前后快照, 返回回滚句柄
//      int (*il_rollback)(int handle);
```

约束：只做体长不变改写；紧致异常表兼容性由「模板仅出现在无异常子句或 body 头部」检查保证，不满足则拒绝并日志说明。

## 4. IL2CPP：不加机制（v1 设计降级为可选便利）

维持一期工作流：**Il2CppDumper → IDA 命名脚本 → RVA → SYR_HOOK**。
唯一可选保留（不进二期必做项）：`SYR_IL2CPP_HOOK` 式符号登记作为**迭代加速器**——
赛前如果已知 Unity 版本，运行时 `il2cpp_class_get_method_from_name` 一跳拿地址，
省去每题 dump+IDA。实现即 v1 设计的 §2（导出解析 + MethodInfo 偏移探测），
但它排在 §2/§3 之后，且砍掉 `.syu64` 延迟安装队列（IL2CPP 模块未加载时直接报
`MODULE_NOT_FOUND`，操作员重试即可——IDC 主路径不受影响）。

## 5. CFG / CRT（横切，结论不变）

- **CFG**：MinHook 函数头 patch 天然免疫 CFG（patch 的就是位图内合法目标）。受影响仅两场景：任意地址牵引 cast 调用、动态生成 stub 执行 → 引擎提供 `cfg_validate(addr)`（SetProcessValidCallTargets 封装）+ `cfg_status()`；Unity 默认不开 /guard:cf，检测优先。
- **CRT/堆**：payload 恒 `/MT`；CRT 分配器钩子与 HeapWalk 快照属一期能力+模板（malloc 也是 ucrtbase 里的 sub_，IDA 可逆）；托管对象不走 CRT 堆，定位走 §2 的 mono 反射函数，不新增机制。

## 6. Api 汇总（v4：尾部追加一个子表指针，SYR_API_MIN 不动）

```cpp
struct UnityApi {
  int version;                                   // UNITY_API_MIN = 1
  int (*backend)(void);                          // 0=NONE 1=IL2CPP 2=MONO
  // Mono(必需)
  uintptr_t (*mono_resolve)(const char* image, const char* ns, const char* cls,
                            const char* method, int argc);
  int (*mono_ensure_thread)(void);
  int (*mono_invoke)(void* method_info, void** args);   // 观测/构造调用(可选)
  // IL 补丁(可选)
  int (*il_patch)(const char* image, const char* ns, const char* cls,
                  const char* method, int argc, int tmpl, int64_t imm);
  int (*il_rollback)(int handle);
  // IL2CPP 便利定位(可选)
  uintptr_t (*il2cpp_resolve)(const char* asm_name, const char* ns,
                              const char* cls, const char* method, int argc);
  // CFG(必需, 一行封装)
  int (*cfg_status)(void);
  int (*cfg_validate)(uintptr_t addr, size_t len);
};
// 主 Api 尾部追加: const UnityApi* (*unity)(void);
```

## 7. 里程碑（修订后，工作量约为 v1 的 1/3）

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| U1 | CFG `cfg_status/validate`（小）+ mono 解析表与 `mono_resolve` | cfg-puppet（/guard:cf 样例）+ mono-puppet：按名字解析出 JIT 地址并 SYR_HOOK 跳过方法 |
| U2 | IL 模板 4 个 + 回滚 | mono-puppet：no-op 化、常量改写、回滚还原 |
| U3（可选） | `il2cpp_resolve` 便利定位 | 真实 Unity IL2CPP 构建各 1 例 |

测试基建：`test/mono_puppet/`——64 位 native 宿主加载 mono-2.0-bdwgc 跑自编译 C# 程序集，发布函数与类名固定，可全自动 e2e；真实 Unity 构建仅 U3 需要手动样例（README 记录步骤）。

— 修订版完。核心变化：IL2CPP 回归「纯一期工作流」，Mono 的新增收缩为「运行时地址解析 + 可选 IL 模板」，CFG 维持小封装。
