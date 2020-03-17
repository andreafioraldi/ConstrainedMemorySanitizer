//===-- cmsan_stack.cpp ---------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// Code for CMSan stack trace.
//===----------------------------------------------------------------------===//

#include "cmsan_stack.h"
#include "cmsan_internal.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

using namespace __cmsan;

void __sanitizer::BufferedStackTrace::UnwindImpl(uptr pc, uptr bp,
                                                 void *context,
                                                 bool request_fast,
                                                 u32 max_depth) {
  uptr top = 0;
  uptr bottom = 0;
  if (StackTrace::WillUseFastUnwind(request_fast)) {
    GetThreadStackTopAndBottom(false, &top, &bottom);
    Unwind(max_depth, pc, bp, nullptr, top, bottom, true);
  } else
    Unwind(max_depth, pc, bp, context, 0, 0, false);
}

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_print_stack_trace() {
  GET_CURRENT_PC_BP;
  BufferedStackTrace stack;
  stack.Unwind(pc, bp, nullptr, common_flags()->fast_unwind_on_fatal);
  stack.Print();
}
} // extern "C"
