//===-- cmsan_linux.cpp ---------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// Linux-specific details.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_FREEBSD || SANITIZER_LINUX || SANITIZER_NETBSD ||                \
    SANITIZER_SOLARIS

#include "cmsan_internal.h"
#include "cmsan_mapping.h"
// #include "cmsan_thread.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_freebsd.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_procmaps.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <unwind.h>

#if SANITIZER_FREEBSD
#include <sys/link_elf.h>
#endif

#if SANITIZER_SOLARIS
#include <link.h>
#endif

#if SANITIZER_ANDROID || SANITIZER_FREEBSD || SANITIZER_SOLARIS
#include <ucontext.h>
extern "C" void *_DYNAMIC;
#elif SANITIZER_NETBSD
#include <link_elf.h>
#include <ucontext.h>
extern Elf_Dyn _DYNAMIC;
#else
#include <link.h>
#include <sys/ucontext.h>
#endif

// x86-64 FreeBSD 9.2 and older define 'ucontext_t' incorrectly in
// 32-bit mode.
#if SANITIZER_FREEBSD && (SANITIZER_WORDSIZE == 32) &&                         \
    __FreeBSD_version <= 902001 // v9.2
#define ucontext_t xucontext_t
#endif

namespace __cmsan {

static void UnmapFromTo(uptr from, uptr to) {
  CHECK(to >= from);
  if (to == from)
    return;
  uptr res = internal_munmap(reinterpret_cast<void *>(from), to - from);
  if (UNLIKELY(internal_iserror(res))) {
    Report("ERROR: ConstrainedMemorySanitizer failed to unmap 0x%zx (%zd) "
           "bytes at address %p\n",
           to - from, to - from, from);
    CHECK("unable to unmap" && 0);
  }
}

uptr FindDynamicShadowStart() {
  // #if CMSAN_PREMAP_SHADOW // not supported ATM
  //  if (!PremapShadowFailed())
  //    return FindPremappedShadowStart();
  // #endif

  uptr granularity = GetMmapGranularity();
  uptr alignment = granularity * 8;
  uptr left_padding = granularity;
  uptr shadow_size = RoundUpTo(kHighShadowEnd, granularity);
  uptr map_size = shadow_size + left_padding + alignment;

  uptr map_start = (uptr)MmapNoAccess(map_size);
  CHECK_NE(map_start, ~(uptr)0);

  uptr shadow_start = RoundUpTo(map_start + left_padding, alignment);
  UnmapFromTo(map_start, shadow_start - left_padding);
  UnmapFromTo(shadow_start + shadow_size, map_start + map_size);

  return shadow_start;
}

} // namespace __cmsan

#endif // SANITIZER_FREEBSD || SANITIZER_LINUX || SANITIZER_NETBSD ||
       // SANITIZER_SOLARIS
