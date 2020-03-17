//===-- cmsan_flags.h -------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
//===----------------------------------------------------------------------===//
#ifndef CMSAN_FLAGS_H
#define CMSAN_FLAGS_H

namespace __cmsan {

struct Flags {
#define CMSAN_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "cmsan_flags.inc"
#undef CMSAN_FLAG

  void SetDefaults();
};

Flags *flags();

void InitializeFlags();

} // namespace __cmsan

#endif // MSAN_FLAGS_H
