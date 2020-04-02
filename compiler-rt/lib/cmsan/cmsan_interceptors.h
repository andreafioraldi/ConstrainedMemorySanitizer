//===-- cmsan_interceptors.h ------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// CMSan-private header for cmsan_interceptors.cpp
//===----------------------------------------------------------------------===//
#ifndef CMSAN_INTERCEPTORS_H
#define CMSAN_INTERCEPTORS_H

#include "cmsan_internal.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"

namespace __cmsan {

void InitializeCmsanInterceptors();

}  // namespace __cmsan

#if !SANITIZER_MAC
#define CMSAN_INTERCEPT_FUNC(name)                                          \
  do {                                                                      \
    if (!INTERCEPT_FUNCTION(name))                                          \
      VReport(1, "ConstrainedMemorySanitizer: failed to intercept '%s'\n'", \
              #name);                                                       \
  } while (0)
#define ASAN_INTERCEPT_FUNC_VER(name, ver)                                  \
  do {                                                                      \
    if (!INTERCEPT_FUNCTION_VER(name, ver))                                 \
      VReport(1, "ConstrainedMemorySanitizer: failed to intercept"          \
              " '%s@@%s'\n", #name, #ver); \                                \
  } while (0)
#else
// OS X interceptors don't need to be initialized with INTERCEPT_FUNCTION.
#define ASAN_INTERCEPT_FUNC(name)
#endif  // SANITIZER_MAC

#endif  // CMSAN_INTERCEPTORS_H
