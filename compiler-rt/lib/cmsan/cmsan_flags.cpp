//===-- cmsan_flags.cpp -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// CMSan flag parsing logic.
//===----------------------------------------------------------------------===//

#include "cmsan_flags.h"
#include "cmsan_interface_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "ubsan/ubsan_flags.h"
#include "ubsan/ubsan_platform.h"

namespace __cmsan {

static Flags cmsan_flags;

Flags *flags() { return &cmsan_flags; }

void Flags::SetDefaults() {
#define CMSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "cmsan_flags.inc"
#undef CMSAN_FLAG
}

static void RegisterCmsanFlags(FlagParser *parser, Flags *f) {
#define CMSAN_FLAG(Type, Name, DefaultValue, Description)                      \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "cmsan_flags.inc"
#undef CMSAN_FLAG
}

void InitializeFlags() {
  SetCommonFlagsDefaults();
  {
    CommonFlags cf;
    cf.CopyFrom(*common_flags());
    cf.external_symbolizer_path = GetEnv("CMSAN_SYMBOLIZER_PATH");
    cf.exitcode = 1;
    OverrideCommonFlags(cf);
  }

  Flags *f = flags();
  f->SetDefaults();

  FlagParser parser;
  RegisterCmsanFlags(&parser, f);
  RegisterCommonFlags(&parser);

#if CAN_SANITIZE_UB
  __ubsan::Flags *uf = __ubsan::flags();
  uf->SetDefaults();

  FlagParser ubsan_parser;
  __ubsan::RegisterUbsanFlags(&ubsan_parser, uf);
  RegisterCommonFlags(&ubsan_parser);
#endif

  // Override from user-specified string.
  if (__cmsan_default_options)
    parser.ParseString(__cmsan_default_options());
#if CAN_SANITIZE_UB
  const char *ubsan_default_options = __ubsan::MaybeCallUbsanDefaultOptions();
  ubsan_parser.ParseString(ubsan_default_options);
#endif

  parser.ParseStringFromEnv("CMSAN_OPTIONS");
#if CAN_SANITIZE_UB
  ubsan_parser.ParseStringFromEnv("UBSAN_OPTIONS");
#endif

  InitializeCommonFlags();

  if (Verbosity())
    ReportUnrecognizedFlags();

  if (common_flags()->help)
    parser.PrintFlagDescriptions();
}

} // namespace __cmsan

SANITIZER_INTERFACE_WEAK_DEF(const char *, __cmsan_default_options, void) {
  return "";
}
