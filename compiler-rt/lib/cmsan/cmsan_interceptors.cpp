//===-- cmsan_interceptors.cpp --------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// Intercept various libc functions.
//===----------------------------------------------------------------------===//

#include "cmsan_interceptors.h"
#include "cmsan_internal.h"
#include "sanitizer_common/sanitizer_libc.h"

// ---------------------- Wrappers ---------------- {{{1
using namespace __cmsan;

extern "C" uptr malloc_usable_size(void*);

INTERCEPTOR(void, free, void *ptr) {
  uptr size = malloc_usable_size(ptr);
  __cmsan_unconstrainN((uptr)ptr, (uptr)size);
  REAL(free)(ptr);
}

// ---------------------- InitializeCmsanInterceptors ---------------- {{{1
namespace __cmsan {
void InitializeCmsanInterceptors() {
  static bool was_called_once;
  CHECK(!was_called_once);
  was_called_once = true;

  CMSAN_INTERCEPT_FUNC(free);

  VReport(1, "ConstrainedMemorySanitizer: libc interceptors initialized\n");
}

} // __cmsan
