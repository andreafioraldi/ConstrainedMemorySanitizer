//===-- cmsan_rtl.cpp -----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// Main file of the CMSan run-time library.
//===----------------------------------------------------------------------===//

#include "cmsan_internal.h"
#include "cmsan_interval.h"
#include "cmsan_mapping.h"
#include "cmsan_stack.h"
#include "lsan/lsan_common.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_symbolizer.h"
#include "ubsan/ubsan_init.h"
#include "ubsan/ubsan_platform.h"

#include <mutex>
#include <shared_mutex>

uptr __cmsan_shadow_memory_dynamic_address; // Global interface symbol.

namespace __cmsan {

static void CmsanDie() {
  static atomic_uint32_t num_calls;
  if (atomic_fetch_add(&num_calls, 1, memory_order_relaxed) != 0) {
    // Don't die twice - run a busy loop.
    while (1) {
    }
  }
  if (common_flags()->print_module_map >= 1)
    PrintModuleMap();
  if (flags()->sleep_before_dying) {
    Report("Sleeping for %d second(s)\n", flags()->sleep_before_dying);
    SleepForSeconds(flags()->sleep_before_dying);
  }
  if (flags()->unmap_shadow_on_exit) {
    if (kMidMemBeg) {
      UnmapOrDie((void *)kLowShadowBeg, kMidMemBeg - kLowShadowBeg);
      UnmapOrDie((void *)kMidMemEnd, kHighShadowEnd - kMidMemEnd);
    } else {
      if (kHighShadowEnd)
        UnmapOrDie((void *)kLowShadowBeg, kHighShadowEnd - kLowShadowBeg);
    }
  }
}

static void CmsanCheckFailed(const char *file, int line, const char *cond,
                             u64 v1, u64 v2) {
  Report(
      "ConstrainedMemorySanitizer CHECK failed: %s:%d \"%s\" (0x%zx, 0x%zx)\n",
      file, line, cond, (uptr)v1, (uptr)v2);

  // Print a stack trace the first time we come here. Otherwise, we probably
  // failed a CHECK during symbolization.
  static atomic_uint32_t num_calls;
  if (atomic_fetch_add(&num_calls, 1, memory_order_relaxed) == 0) {
    PRINT_CURRENT_STACK_CHECK();
  }

  Die();
}

// -------------------------- Globals --------------------- {{{1
int cmsan_inited;
bool cmsan_init_is_running;

#if !CMSAN_FIXED_MAPPING
uptr kHighMemEnd, kMidMemBeg, kMidMemEnd;
#endif

// Force the linker to keep the symbols for various CMSan interface functions.
// We want to keep those in the executable in order to let the instrumented
// dynamic libraries access the symbol even if it is not used by the executable
// itself. This should help if the build system is removing dead code at link
// time.
static NOINLINE void force_interface_symbols() {
  volatile int fake_condition = 0; // prevent dead condition elimination.
  // clang-format off
  switch (fake_condition) {
    case 1: __cmsan_load1(0); break;
    case 2: __cmsan_load2(0); break;
    case 3: __cmsan_load4(0); break;
    case 4: __cmsan_load8(0); break;
    case 5: __cmsan_loadN(0, 0); break;
    case 6: __cmsan_store1(0); break;
    case 7: __cmsan_store2(0); break;
    case 8: __cmsan_store4(0); break;
    case 9: __cmsan_store8(0); break;
    case 10: __cmsan_storeN(0, 0); break;
    case 11: __cmsan_constrain1(0, 0); break;
    case 12: __cmsan_constrain2(0, 0); break;
    case 13: __cmsan_constrain4(0, 0); break;
    case 14: __cmsan_constrain8(0, 0); break;
    case 15: __cmsan_constrainN(0, 0, 0); break;
    case 16: __cmsan_unconstrain1(0); break;
    case 17: __cmsan_unconstrain2(0); break;
    case 18: __cmsan_unconstrain4(0); break;
    case 19: __cmsan_unconstrain8(0); break;
    case 20: __cmsan_unconstrainN(0, 0); break;
  }
  // clang-format on
}

static void InitializeHighMemEnd() {
#if !CMSAN_FIXED_MAPPING
  kHighMemEnd = GetMaxUserVirtualAddress();
  // Increase kHighMemEnd to make sure it's properly
  // aligned together with kHighMemBeg:
  kHighMemEnd |= SHADOW_GRANULARITY * GetMmapGranularity() - 1;
#endif // !CMSAN_FIXED_MAPPING
  CHECK_EQ((kHighMemBeg % GetMmapGranularity()), 0);
}

void PrintAddressSpaceLayout() {
  if (kHighMemBeg) {
    Printf("|| `[%p, %p]` || HighMem    ||\n", (void *)kHighMemBeg,
           (void *)kHighMemEnd);
    Printf("|| `[%p, %p]` || HighShadow ||\n", (void *)kHighShadowBeg,
           (void *)kHighShadowEnd);
  }
  if (kMidMemBeg) {
    Printf("|| `[%p, %p]` || ShadowGap3 ||\n", (void *)kShadowGap3Beg,
           (void *)kShadowGap3End);
    Printf("|| `[%p, %p]` || MidMem     ||\n", (void *)kMidMemBeg,
           (void *)kMidMemEnd);
    Printf("|| `[%p, %p]` || ShadowGap2 ||\n", (void *)kShadowGap2Beg,
           (void *)kShadowGap2End);
    Printf("|| `[%p, %p]` || MidShadow  ||\n", (void *)kMidShadowBeg,
           (void *)kMidShadowEnd);
  }
  Printf("|| `[%p, %p]` || ShadowGap  ||\n", (void *)kShadowGapBeg,
         (void *)kShadowGapEnd);
  if (kLowShadowBeg) {
    Printf("|| `[%p, %p]` || LowShadow  ||\n", (void *)kLowShadowBeg,
           (void *)kLowShadowEnd);
    Printf("|| `[%p, %p]` || LowMem     ||\n", (void *)kLowMemBeg,
           (void *)kLowMemEnd);
  }
  Printf("MemToShadow(shadow): %p %p", (void *)MEM_TO_SHADOW(kLowShadowBeg),
         (void *)MEM_TO_SHADOW(kLowShadowEnd));
  if (kHighMemBeg) {
    Printf(" %p %p", (void *)MEM_TO_SHADOW(kHighShadowBeg),
           (void *)MEM_TO_SHADOW(kHighShadowEnd));
  }
  if (kMidMemBeg) {
    Printf(" %p %p", (void *)MEM_TO_SHADOW(kMidShadowBeg),
           (void *)MEM_TO_SHADOW(kMidShadowEnd));
  }
  Printf("\n");

  Printf("SHADOW_SCALE: %d\n", (int)SHADOW_SCALE);
  Printf("SHADOW_GRANULARITY: %d\n", (int)SHADOW_GRANULARITY);
  Printf("SHADOW_OFFSET: 0x%zx\n", (uptr)SHADOW_OFFSET);
  CHECK(SHADOW_SCALE >= 3 && SHADOW_SCALE <= 7);
  if (kMidMemBeg)
    CHECK(kMidShadowBeg > kLowShadowEnd && kMidMemBeg > kMidShadowEnd &&
          kHighShadowBeg > kMidMemEnd);
}

static void CmsanInitInternal() {
  if (LIKELY(cmsan_inited))
    return;
  SanitizerToolName = "ConstrainedMemorySanitizer";
  CHECK(!cmsan_init_is_running && "CMSan init calls itself!");
  cmsan_init_is_running = true;

  CacheBinaryName();

  // Initialize flags. This must be done early, because most of the
  // initialization steps look at flags().
  InitializeFlags();

  // Stop performing init at this point if we are being loaded via
  // dlopen() and the platform supports it.
  // if (SANITIZER_SUPPORTS_INIT_FOR_DLOPEN && UNLIKELY(HandleDlopenInit())) {
  //  cmsan_init_is_running = false;
  //  VReport(1, "ConstrainedMemorySanitizer init is being performed for
  //  dlopen().\n"); return;
  //}

  // CmsanCheckIncompatibleRT();
  // CmsanCheckDynamicRTPrereqs(); // TODO(andrea) CMSan Linux at least

  // InitializePlatformExceptionHandlers();

  InitializeHighMemEnd();

  // Make sure we are not statically linked.
  // CmsanDoesNotSupportStaticLinkage();

  // Install tool-specific callbacks in sanitizer_common.
  AddDieCallback(CmsanDie);
  SetCheckFailedCallback(CmsanCheckFailed);
  // SetPrintfAndReportCallback(AppendToErrorMessageBuffer);

  __sanitizer_set_report_path(common_flags()->log_path);

  __sanitizer::InitializePlatformEarly();

  // Re-exec ourselves if we need to set additional env or command line args.
  MaybeReexec();

  // InitializeCmsanInterceptors();
  CheckASLR();

  // Enable system log ("adb logcat") on Android.
  // Doing this before interceptors are initialized crashes in:
  // CmsanInitInternal -> android_log_write -> __interceptor_strcmp
  // AndroidLogInit();

  DisableCoreDumperIfNecessary();

  InitializeShadowMemory();

  // On Linux CmsanThread::ThreadStart() calls malloc() that's why cmsan_inited
  // should be set to 1 prior to initializing the threads.
  cmsan_inited = 1;
  cmsan_init_is_running = false;

  // if (flags()->atexit)
  //  Atexit(cmsan_atexit);

  // Create main thread.
  // CmsanThread *main_thread = CreateMainThread();
  // CHECK_EQ(0, main_thread->tid());
  force_interface_symbols(); // no-op.
  SanitizerInitializeUnwinder();

#if CAN_SANITIZE_UB
  __ubsan::InitAsPlugin();
#endif

  Symbolizer::LateInitialize();

  VReport(1, "ConstrainedMemorySanitizer Init done\n");

  if (flags()->sleep_after_init) {
    Report("Sleeping for %d second(s)\n", flags()->sleep_after_init);
    SleepForSeconds(flags()->sleep_after_init);
  }
}

static std::shared_timed_mutex cmsan_mut;

static inline void CmsanTagMemory(uintptr_t start, uintptr_t end, void *fn,
                                  uint8_t type) {
  std::unique_lock<std::shared_timed_mutex> lock(cmsan_mut, std::defer_lock);
  lock.lock();
  CmsanIntervalSet(start, end, fn, type);
}

static inline void CmsanUntagMemory(uintptr_t start, uintptr_t end) {
  std::unique_lock<std::shared_timed_mutex> lock(cmsan_mut, std::defer_lock);
  lock.lock();
  CmsanIntervalUnset(start, end);
}

static inline void CmsanHitMemory(uptr start, uptr end, bool is_write) {
  std::shared_lock<std::shared_timed_mutex> lock(cmsan_mut, std::defer_lock);
  lock.lock();
  CmsanIntervalExecuteAll(start, end);
}

static inline __attribute__((always_inline)) u8 CmsanGetBit(uptr base,
                                                            uptr idx) {
  return ((u8 *)(base))[idx >> 3] & (128 >> (idx & 7));
}

static inline __attribute__((always_inline)) void CmsanSetBit(uptr base,
                                                              uptr idx) {
  ((u8 *)base)[idx >> 3] |= (128 >> (idx & 7));
}

static inline __attribute__((always_inline)) void CmsanUnsetBit(uptr base,
                                                                uptr idx) {
  ((u8 *)base)[idx >> 3] &= ~(128 >> (idx & 7));
}

#define CMSAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, exp_arg)       \
  /* if (!AddrIsInMem(addr) && !AddrIsInShadow(addr))                          \
    return;  */                                                                \
  uptr mask = 0;                                                               \
  uptr iter = addr;                                                            \
  uptr end = iter + size;                                                      \
  while (iter < end)                                                           \
    mask |= CmsanGetBit(SHADOW_OFFSET, iter++);                                \
  if (mask)                                                                    \
    CmsanHitMemory(addr, end, is_write);

#define CMSAN_MEMORY_ACCESS_CALLBACK(type, is_write, size)                     \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __cmsan_##type##size(           \
      uptr addr) {                                                             \
    CMSAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, 0)                 \
  }                                                                            \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __cmsan_exp_##type##size(       \
      uptr addr, u32 exp) {                                                    \
    CMSAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, exp)               \
  }

CMSAN_MEMORY_ACCESS_CALLBACK(load, false, 1)
CMSAN_MEMORY_ACCESS_CALLBACK(load, false, 2)
CMSAN_MEMORY_ACCESS_CALLBACK(load, false, 4)
CMSAN_MEMORY_ACCESS_CALLBACK(load, false, 8)
CMSAN_MEMORY_ACCESS_CALLBACK(load, false, 16)
CMSAN_MEMORY_ACCESS_CALLBACK(store, true, 1)
CMSAN_MEMORY_ACCESS_CALLBACK(store, true, 2)
CMSAN_MEMORY_ACCESS_CALLBACK(store, true, 4)
CMSAN_MEMORY_ACCESS_CALLBACK(store, true, 8)
CMSAN_MEMORY_ACCESS_CALLBACK(store, true, 16)

#define CMSAN_MEMORY_ACCESS_CALLBACK_N(type, is_write)                         \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __cmsan_##type##N(uptr addr,    \
                                                                 uptr size) {  \
    CMSAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, 0)                 \
  }                                                                            \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __cmsan_exp_##type##N(          \
      uptr addr, uptr size, u32 exp) {                                         \
    CMSAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, exp)               \
  }

CMSAN_MEMORY_ACCESS_CALLBACK_N(load, false)
CMSAN_MEMORY_ACCESS_CALLBACK_N(store, true)

#define CMSAN_CONSTRAIN_CALLBACK(size)                                         \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __cmsan_constrain##size(        \
      uptr addr, ConstrainFunc##size func) {                                   \
    CHECK(addr + size > addr);                                                 \
    uptr iter = addr;                                                          \
    uptr end = iter + size;                                                    \
    CmsanTagMemory(addr, end, (void *)func, CONSTRAINFUNC##size##TY);          \
    while (iter < end)                                                         \
      CmsanSetBit(SHADOW_OFFSET, iter++);                                      \
  }

#define CMSAN_UNCONSTRAIN_CALLBACK(size)                                       \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __cmsan_unconstrain##size(      \
      uptr addr) {                                                             \
    CHECK(addr + size > addr);                                                 \
    uptr iter = addr;                                                          \
    uptr end = iter + size;                                                    \
    CmsanUntagMemory(addr, end);                                               \
    while (iter < end)                                                         \
      CmsanSetBit(SHADOW_OFFSET, iter++);                                      \
  }

CMSAN_CONSTRAIN_CALLBACK(1)
CMSAN_CONSTRAIN_CALLBACK(2)
CMSAN_CONSTRAIN_CALLBACK(4)
CMSAN_CONSTRAIN_CALLBACK(8)
CMSAN_CONSTRAIN_CALLBACK(16)
CMSAN_UNCONSTRAIN_CALLBACK(1)
CMSAN_UNCONSTRAIN_CALLBACK(2)
CMSAN_UNCONSTRAIN_CALLBACK(4)
CMSAN_UNCONSTRAIN_CALLBACK(8)
CMSAN_UNCONSTRAIN_CALLBACK(16)

extern "C" NOINLINE INTERFACE_ATTRIBUTE void
__cmsan_constrainN(uptr addr, uptr size, ConstrainFuncN func) {
  CHECK(addr + size > addr);
  uptr iter = addr;
  uptr end = iter + size;
  CmsanTagMemory(addr, end, (void *)func, CONSTRAINFUNCNTY);
  while (iter < end)
    CmsanSetBit(SHADOW_OFFSET, iter++);
}

extern "C" NOINLINE INTERFACE_ATTRIBUTE void __cmsan_unconstrainN(uptr addr,
                                                                  uptr size) {
  CHECK(addr + size > addr);
  uptr iter = addr;
  uptr end = iter + size;
  CmsanUntagMemory(addr, end);
  while (iter < end)
    CmsanUnsetBit(SHADOW_OFFSET, iter++);
}

} // namespace __cmsan

// ---------------------- Interface ---------------- {{{1
using namespace __cmsan;

extern "C" NOINLINE INTERFACE_ATTRIBUTE void __cmsan_assert(int boolean) {
  if (!boolean) {
    Report("ConstrainedMemorySanitizer ASSERT failed\n");

    PRINT_CURRENT_STACK_CHECK();
    Die();
  }
}

// Initialize as requested from instrumented application code.
extern "C" NOINLINE INTERFACE_ATTRIBUTE void __cmsan_init() {
  CmsanInitInternal();
}
