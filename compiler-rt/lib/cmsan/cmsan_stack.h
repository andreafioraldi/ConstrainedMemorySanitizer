//===-- cmsan_stack.h -------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// CMSan-private header for asan_stack.cpp.
//===----------------------------------------------------------------------===//

#ifndef CMSAN_STACK_H
#define CMSAN_STACK_H

#include "cmsan_flags.h"
//#include "cmsan_thread.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

// NOTE: A Rule of thumb is to retrieve stack trace in the interceptors
// as early as possible (in functions exposed to the user), as we generally
// don't want stack trace to contain functions from CMSan internals.

#define GET_STACK_TRACE(max_size, fast)                                        \
  BufferedStackTrace stack;                                                    \
  if (max_size <= 2) {                                                         \
    stack.size = max_size;                                                     \
    if (max_size > 0) {                                                        \
      stack.top_frame_bp = GET_CURRENT_FRAME();                                \
      stack.trace_buffer[0] = StackTrace::GetCurrentPc();                      \
      if (max_size > 1)                                                        \
        stack.trace_buffer[1] = GET_CALLER_PC();                               \
    }                                                                          \
  } else {                                                                     \
    stack.Unwind(StackTrace::GetCurrentPc(), GET_CURRENT_FRAME(), nullptr,     \
                 fast, max_size);                                              \
  }

#define GET_STACK_TRACE_FATAL(pc, bp)                                          \
  BufferedStackTrace stack;                                                    \
  stack.Unwind(pc, bp, nullptr, common_flags()->fast_unwind_on_fatal)

#define GET_STACK_TRACE_SIGNAL(sig)                                            \
  BufferedStackTrace stack;                                                    \
  stack.Unwind((sig).pc, (sig).bp, (sig).context,                              \
               common_flags()->fast_unwind_on_fatal)

#define GET_STACK_TRACE_FATAL_HERE                                             \
  GET_STACK_TRACE(kStackTraceMax, common_flags()->fast_unwind_on_fatal)

#define GET_STACK_TRACE_CHECK_HERE                                             \
  GET_STACK_TRACE(kStackTraceMax, common_flags()->fast_unwind_on_check)

#define GET_STACK_TRACE_THREAD GET_STACK_TRACE(kStackTraceMax, true)

#define GET_STACK_TRACE_MALLOC                                                 \
  GET_STACK_TRACE(GetMallocContextSize(), common_flags()->fast_unwind_on_malloc)

#define GET_STACK_TRACE_FREE GET_STACK_TRACE_MALLOC

#define PRINT_CURRENT_STACK()                                                  \
  {                                                                            \
    GET_STACK_TRACE_FATAL_HERE;                                                \
    stack.Print();                                                             \
  }

#define PRINT_CURRENT_STACK_CHECK()                                            \
  {                                                                            \
    GET_STACK_TRACE_CHECK_HERE;                                                \
    stack.Print();                                                             \
  }

#endif // CMSAN_STACK_H
