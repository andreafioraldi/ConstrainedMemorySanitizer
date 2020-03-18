//===-- cmsan_interceptors_memintrinsics.cpp ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// CMSan versions of memcpy, memmove, and memset.
//===---------------------------------------------------------------------===//

#include "cmsan_interface_internal.h"
#include "sanitizer_common/sanitizer_libc.h"

using namespace __cmsan;

void *__cmsan_memcpy(void *to, const void *from, uptr size) {
  return internal_memcpy(to, from, size); // TODO
}

void *__cmsan_memset(void *block, int c, uptr size) {
  return internal_memset(block, c, size); // TODO
}

void *__cmsan_memmove(void *to, const void *from, uptr size) {
  return internal_memmove(to, from, size); // TODO
}
