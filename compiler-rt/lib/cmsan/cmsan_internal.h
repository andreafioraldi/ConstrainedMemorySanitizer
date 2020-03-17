//===-- cmsan_internal.h ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// CMSan-private header which defines various general utilities.
//===----------------------------------------------------------------------===//
#ifndef CMSAN_INTERNAL_H
#define CMSAN_INTERNAL_H

#include "cmsan_flags.h"
#include "cmsan_interface_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

// Build-time configuration options.

#ifndef CMSAN_DYNAMIC
#ifdef PIC
#define CMSAN_DYNAMIC 1
#else
#define CMSAN_DYNAMIC 0
#endif
#endif

// All internal functions in asan reside inside the __cmsan namespace
// to avoid namespace collisions with the user programs.
// Separate namespace also makes it simpler to distinguish the asan run-time
// functions from the instrumented user code in a profile.
namespace __cmsan {

using __sanitizer::StackTrace;

// cmsan_rtl.cpp
void PrintAddressSpaceLayout();
void NORETURN ShowStatsAndAbort();

// cmsan_shadow_setup.cpp
void InitializeShadowMemory();

void ReadContextStack(void *context, uptr *stack, uptr *ssize);
void StopInitOrderChecking();

void AppendToErrorMessageBuffer(const char *buffer);

void *CmsanDlSymNext(const char *sym);

void ReserveShadowMemoryRange(uptr beg, uptr end, const char *name);

uptr FindDynamicShadowStart();

// CmsanThread *CreateMainThread();

extern int cmsan_inited;
// Used to avoid infinite recursion in __cmsan_init().
extern bool cmsan_init_is_running;

} // namespace __cmsan

#endif // CMSAN_INTERNAL_H
