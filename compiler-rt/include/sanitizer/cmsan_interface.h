//===-- cmsan_interface.h -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// Public interface header.
//===----------------------------------------------------------------------===//
#ifndef CMSAN_INTERFACE_H
#define CMSAN_INTERFACE_H

#include <sanitizer/common_interface_defs.h>

#ifndef UINT128MAX
#define CMSAN_U128P __uint128_t*
#else
#define CMSAN_U128P void*
#endif

typedef void (*ConstrainFunc1)(uint8_t *);
typedef void (*ConstrainFunc2)(uint16_t *);
typedef void (*ConstrainFunc4)(uint32_t *);
typedef void (*ConstrainFunc8)(uint64_t *);
typedef void (*ConstrainFunc16)(CMSAN_U128P);
typedef void (*ConstrainFuncN)(const volatile void *, size_t);

#define __cmsan_assert(EXP) \
  do { \
    int __cmsan_cond = (int)(EXP); \
    if (!__cmsan_cond) \
      __cmsan_trigger_assert(__FILE__, __LINE__, #EXP, __cmsan_cond, 0); \
  } while(0)

#define CMSAN_ASSERT __cmsan_assert

#if defined(__GNUC__)
#define __cmsan_assert_op(V1, OP, V2) \
  do { \
    __typeof__(V1) __cmsan_v1 = (V1); \
    __typeof__(V2) __cmsan_v2 = (V2); \
    if (!(int)(__cmsan_v1 OP __cmsan_v2)) \
      __cmsan_trigger_assert(__FILE__, __LINE__, #V1 " " #OP " " #V2, \
                             __cmsan_v1, __cmsan_v2); \
  } while(0)
#else
// don't do side effects when evaluating V1 and V2 !!!
#define __cmsan_assert_op(V1, OP, V2) \
  do { \
    if (!(int)(V1 OP V2)) \
      __cmsan_trigger_assert(__FILE__, __LINE__, #V1 #OP #V2, V1, V2); \
  } while(0)
#endif

#define CMSAN_ASSERT_OP __cmsan_assert_op

#define CMSAN_ASSERT_LT(V1, V2) __cmsan_assert_op(V1, <, V2)
#define CMSAN_ASSERT_LE(V1, V2) __cmsan_assert_op(V1, <=, V2)
#define CMSAN_ASSERT_GT(V1, V2) __cmsan_assert_op(V1, >, V2)
#define CMSAN_ASSERT_GE(V1, V2) __cmsan_assert_op(V1, >=, V2)
#define CMSAN_ASSERT_EQ(V1, V2) __cmsan_assert_op(V1, ==, V2)
#define CMSAN_ASSERT_NE(V1, V2) __cmsan_assert_op(V1, !=, V2)

#define CMSAN_OFFSETOF(st, m) \
  ((size_t)&(((st *)0)->m))

#define CMSAN_BASEOF(st, m, ptr) \
  (st*)((uint8_t*)(ptr) - offsetof(st, m))

#ifdef __cplusplus
extern "C" {
#endif

void __cmsan_loadN(const volatile void *p, size_t size);
void __cmsan_storeN(const volatile void *p, size_t size);

void __cmsan_constrain1(uint8_t *p, ConstrainFunc1 fn);
void __cmsan_constrain2(uint16_t *p, ConstrainFunc2 fn);
void __cmsan_constrain4(uint32_t *p, ConstrainFunc4 fn);
void __cmsan_constrain8(uint64_t *p, ConstrainFunc8 fn);
void __cmsan_constrain16(CMSAN_U128P p, ConstrainFunc16 fn);
void __cmsan_constrainN(const volatile void *p, size_t size, ConstrainFuncN fn);
void __cmsan_unconstrain1(uint8_t *p);
void __cmsan_unconstrain2(uint16_t *p);
void __cmsan_unconstrain4(uint32_t *p);
void __cmsan_unconstrain8(uint64_t *p);
void __cmsan_unconstrain16(CMSAN_U128P p);
void __cmsan_unconstrainN(const volatile void *p, size_t size);

void __cmsan_trigger_assert(const char *file, int line, const char* cond,
                            uint64_t v1, uint64_t v2);
void __cmsan_basic_assert(int boolean);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
