// core_exports.hpp —— tether/ctl 侧对 syr_core.cpp 导出符号的薄封装声明。
#pragma once
#include <windows.h>
#include <cstdint>
#include "syringe.hpp"

extern "C" {
int           SyrInit(void);
uintptr_t     SyrModuleBase(const wchar_t* module);
int           SyrHookRegister(uintptr_t target, void* detour, void** original,
                              const char* name);
int           SyrHookRemove(uintptr_t target);
int           SyrWriteMem(uintptr_t addr, const void* buf, size_t len);
int           SyrReadMem(uintptr_t addr, void* buf, size_t len);
uintptr_t     SyrAllocMem(size_t size, int exec);
void          SyrFreeMem(uintptr_t addr);
uint32_t      SyrProtect(uintptr_t addr, size_t len, uint32_t new_prot);
int           SyrScanRwx(const char* pattern, uintptr_t* out, int max_out);
int           SyrCfgStatus(void);
int           SyrCfgValidate(uintptr_t addr, size_t len);
int           SyrPeSections(uintptr_t base, syr::SectionInfo* out, int max_out);
uintptr_t     SyrPeExport(uintptr_t base, const char* name);
int           SyrScanRange(uintptr_t start, uintptr_t end,
                           const char* pattern, uintptr_t* out, int max_out);
int           SyrCfgBitmapSet(uintptr_t addr);
uintptr_t     SyrCfgBitmapBase(void);
int           SyrScanPattern(const wchar_t* module, const char* pattern,
                             uintptr_t* out, int max_out);
int           SyrInstallSection(void* module);
const char*   SyrGetLog(void);
int           SyrHookCount(void);
const char*   SyrHooksInfo(void);
const syr::Api* SyrGetApi(void);
}

// 薄别名, 供 tether 内部调用
inline int           SyrInitExport(void) { return SyrInit(); }
inline const syr::Api* SyrGetApiTable(void) { return SyrGetApi(); }
inline int           SyrWriteMemExport(uintptr_t a, const void* b, size_t n) { return SyrWriteMem(a, b, n); }
inline int           SyrScanExport(const wchar_t* m, const char* p, uintptr_t* o, int mx) { return SyrScanPattern(m, p, o, mx); }
inline const char*   SyrGetLogExport(void) { return SyrGetLog(); }
inline const char*   SyrHooksInfoExport(void) { return SyrHooksInfo(); }
