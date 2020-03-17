//===-- cmsan_flags.inc -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// CMSan runtime flags.
//
//===----------------------------------------------------------------------===//
#ifndef CMSAN_FLAG
# error "Define CMSAN_FLAG prior to including this file!"
#endif

// CMSAN_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

CMSAN_FLAG(bool, wrap_signals, true, "")
CMSAN_FLAG(bool, protect_shadow_gap, true, "If set, mprotect the shadow gap")
CMSAN_FLAG(bool, print_stats, false, "")
CMSAN_FLAG(bool, atexit, false, "")
CMSAN_FLAG(bool, unmap_shadow_on_exit, false,
          "If set, explicitly unmaps the (huge) shadow at exit.")
CMSAN_FLAG(
    int, sleep_before_dying, 0,
    "Number of seconds to sleep between printing an error report and "
    "terminating the program. Useful for debugging purposes (e.g. when one "
    "needs to attach gdb).")
CMSAN_FLAG(
    int, sleep_after_init, 0,
    "Number of seconds to sleep after ConstrainedMemorySanitizer is initialized. Useful for debugging purposes (e.g. when one needs to attach gdb).")
