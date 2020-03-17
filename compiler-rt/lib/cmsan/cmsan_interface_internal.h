//===-- cmsan_interface_internal.h ------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// This header declares the CMSan runtime interface functions.
// The runtime library has to define these functions so the instrumented program
// could call them.
//
// See also include/sanitizer/cmsan_interface.h
//===----------------------------------------------------------------------===//
#ifndef ASAN_INTERFACE_INTERNAL_H
#define ASAN_INTERFACE_INTERNAL_H

#include "cmsan_constrainfunc_def.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

using __sanitizer::u16;
using __sanitizer::u32;
using __sanitizer::u64;
using __sanitizer::u8;
using __sanitizer::uptr;

extern "C" {
// This function should be called at the very beginning of the process,
// before any instrumented code is executed and before any call to malloc.
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_init();

SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_assert(int boolean);

// These two functions should be called before and after dynamic initializers
// of a single module run, respectively.
SANITIZER_INTERFACE_ATTRIBUTE
void __cmsan_before_dynamic_init(const char *module_name);
SANITIZER_INTERFACE_ATTRIBUTE
void __cmsan_after_dynamic_init();

SANITIZER_INTERFACE_ATTRIBUTE
int __cmsan_address_is_tagged(void const volatile *addr);

SANITIZER_INTERFACE_ATTRIBUTE
uptr __cmsan_region_is_tagged(uptr beg, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
uptr __cmsan_get_report_pc();
SANITIZER_INTERFACE_ATTRIBUTE
uptr __cmsan_get_report_bp();
SANITIZER_INTERFACE_ATTRIBUTE
uptr __cmsan_get_report_sp();
SANITIZER_INTERFACE_ATTRIBUTE
uptr __cmsan_get_report_address();
SANITIZER_INTERFACE_ATTRIBUTE
int __cmsan_get_report_access_type();
SANITIZER_INTERFACE_ATTRIBUTE
uptr __cmsan_get_report_access_size();
SANITIZER_INTERFACE_ATTRIBUTE
const char *__cmsan_get_report_description();

SANITIZER_INTERFACE_ATTRIBUTE
const char *__cmsan_locate_address(uptr addr, char *name, uptr name_size,
                                   uptr *region_address, uptr *region_size);

SANITIZER_INTERFACE_ATTRIBUTE
void __cmsan_report_error(uptr pc, uptr bp, uptr sp, uptr addr, int is_write,
                          uptr access_size, u32 exp);

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void __cmsan_on_error();

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE const char *
__cmsan_default_options();

SANITIZER_INTERFACE_ATTRIBUTE
extern uptr __cmsan_shadow_memory_dynamic_address;

SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_load1(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_load2(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_load4(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_load8(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_load16(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_store1(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_store2(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_store4(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_store8(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_store16(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_loadN(uptr p, uptr size);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_storeN(uptr p, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_load1(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_load2(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_load4(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_load8(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_load16(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_store1(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_store2(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_store4(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_store8(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_store16(uptr p, u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_loadN(uptr p, uptr size,
                                                     u32 exp);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_exp_storeN(uptr p, uptr size,
                                                      u32 exp);

SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_constrain1(uptr p,
                                                      ConstrainFunc1 fn);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_constrain2(uptr p,
                                                      ConstrainFunc2 fn);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_constrain4(uptr p,
                                                      ConstrainFunc4 fn);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_constrain8(uptr p,
                                                      ConstrainFunc8 fn);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_constrain16(uptr p,
                                                       ConstrainFunc16 fn);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_constrainN(uptr p, uptr size,
                                                      ConstrainFuncN fn);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_unconstrain1(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_unconstrain2(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_unconstrain4(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_unconstrain8(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_unconstrain16(uptr p);
SANITIZER_INTERFACE_ATTRIBUTE void __cmsan_unconstrainN(uptr p, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void *__cmsan_memcpy(void *dst, const void *src, uptr size);
SANITIZER_INTERFACE_ATTRIBUTE
void *__cmsan_memset(void *s, int c, uptr n);
SANITIZER_INTERFACE_ATTRIBUTE
void *__cmsan_memmove(void *dest, const void *src, uptr n);
} // extern "C"

#endif // ASAN_INTERFACE_INTERNAL_H
