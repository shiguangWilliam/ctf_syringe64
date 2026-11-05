// payload_second.cpp —— 审计用第二 payload: 零钩子, 只验证
// 「同一活进程内追加加载不同 payload, 注入器/牵引零重编」与 Api 表日志通道。
#include "syringe.hpp"

static int Marker() {
  if (!syr::g_api) return -1;
  syr::g_api->log("payload_second: alive, api v%d", syr::g_api->version);
  uintptr_t p = syr::g_api->alloc_mem(16, 0);
  if (!p) return -2;
  *(unsigned*)p = 0xCAFEBABE;
  int bad = syr::g_api->read_mem(0x10, &p, 8);  // 野指针读应安全失败
  syr::g_api->free_mem(p);
  syr::g_api->log("payload_second: alloc/read/free done, badread=%d", bad);
  return 0;
}

SYR_PAYLOAD_WITH_INIT(Marker)
