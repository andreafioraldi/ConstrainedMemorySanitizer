//===-- cmsan_mapping.h -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ConstrainedMemorySanitizer.
//
// Defines CMSan memory mapping.
//===----------------------------------------------------------------------===//
#ifndef CMSAN_MAPPING_H
#define CMSAN_MAPPING_H

#include "cmsan_internal.h"

// The full explanation of the memory mapping could be found here:
// https://github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm

static const u64 kDefaultShadowScale = 3;
static const u64 kDefaultShadowSentinel = ~(uptr)0;
static const u64 kDefaultShadowOffset32 = 1ULL << 29; // 0x20000000
static const u64 kDefaultShadowOffset64 = 1ULL << 44;
static const u64 kDefaultShort64bitShadowOffset =
    0x7FFFFFFF & (~0xFFFULL << kDefaultShadowScale); // < 2G.
static const u64 kAArch64_ShadowOffset64 = 1ULL << 36;
static const u64 kMIPS32_ShadowOffset32 = 0x0aaa0000;
static const u64 kMIPS64_ShadowOffset64 = 1ULL << 37;
static const u64 kPPC64_ShadowOffset64 = 1ULL << 44;
static const u64 kSystemZ_ShadowOffset64 = 1ULL << 52;
static const u64 kSPARC64_ShadowOffset64 = 1ULL << 43; // 0x80000000000
static const u64 kFreeBSD_ShadowOffset32 = 1ULL << 30; // 0x40000000
static const u64 kFreeBSD_ShadowOffset64 = 1ULL << 46; // 0x400000000000
static const u64 kNetBSD_ShadowOffset32 = 1ULL << 30;  // 0x40000000
static const u64 kNetBSD_ShadowOffset64 = 1ULL << 46;  // 0x400000000000
static const u64 kWindowsShadowOffset32 = 3ULL << 28;  // 0x30000000

#define SHADOW_SCALE kDefaultShadowScale

#if SANITIZER_FUCHSIA
#define SHADOW_OFFSET (0)
#elif SANITIZER_WORDSIZE == 32
#if SANITIZER_ANDROID
#define SHADOW_OFFSET __cmsan_shadow_memory_dynamic_address
#elif defined(__mips__)
#define SHADOW_OFFSET kMIPS32_ShadowOffset32
#elif SANITIZER_FREEBSD
#define SHADOW_OFFSET kFreeBSD_ShadowOffset32
#elif SANITIZER_NETBSD
#define SHADOW_OFFSET kNetBSD_ShadowOffset32
#elif SANITIZER_WINDOWS
#define SHADOW_OFFSET kWindowsShadowOffset32
#elif SANITIZER_IOS
#define SHADOW_OFFSET __cmsan_shadow_memory_dynamic_address
#else
#define SHADOW_OFFSET kDefaultShadowOffset32
#endif
#else
#if SANITIZER_IOS
#define SHADOW_OFFSET __cmsan_shadow_memory_dynamic_address
#elif defined(__aarch64__)
#define SHADOW_OFFSET kAArch64_ShadowOffset64
#elif defined(__powerpc64__)
#define SHADOW_OFFSET kPPC64_ShadowOffset64
#elif defined(__s390x__)
#define SHADOW_OFFSET kSystemZ_ShadowOffset64
#elif SANITIZER_FREEBSD
#define SHADOW_OFFSET kFreeBSD_ShadowOffset64
#elif SANITIZER_NETBSD
#define SHADOW_OFFSET kNetBSD_ShadowOffset64
#elif SANITIZER_MAC
#define SHADOW_OFFSET kDefaultShadowOffset64
#elif defined(__mips64)
#define SHADOW_OFFSET kMIPS64_ShadowOffset64
#elif defined(__sparc__)
#define SHADOW_OFFSET kSPARC64_ShadowOffset64
#elif SANITIZER_WINDOWS64
#define SHADOW_OFFSET __cmsan_shadow_memory_dynamic_address
#else
#define SHADOW_OFFSET kDefaultShort64bitShadowOffset
#endif
#endif

/*
#if SANITIZER_ANDROID && defined(__arm__)
# define CMSAN_PREMAP_SHADOW 1
#else
# define CMSAN_PREMAP_SHADOW 0
#endif
*/

#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)

// If 1, all shadow boundaries are constants.
// Don't set to 1 other than for testing.
#define CMSAN_FIXED_MAPPING 0

namespace __cmsan {

#if CMSAN_FIXED_MAPPING
// Fixed mapping for 64-bit Linux. Mostly used for performance comparison
// with non-fixed mapping. As of r175253 (Feb 2013) the performance
// difference between fixed and non-fixed mapping is below the noise level.
static uptr kHighMemEnd = 0x7fffffffffffULL;
static uptr kMidMemBeg = 0x3000000000ULL;
static uptr kMidMemEnd = 0x4fffffffffULL;
#else
extern uptr kHighMemEnd, kMidMemBeg, kMidMemEnd; // Initialized in __cmsan_init.
#endif

} // namespace __cmsan

#define MEM_TO_SHADOW(mem) (((mem) >> SHADOW_SCALE) + (SHADOW_OFFSET))

#define kLowMemBeg 0
#define kLowMemEnd (SHADOW_OFFSET ? SHADOW_OFFSET - 1 : 0)

#define kLowShadowBeg SHADOW_OFFSET
#define kLowShadowEnd MEM_TO_SHADOW(kLowMemEnd)

#define kHighMemBeg (MEM_TO_SHADOW(kHighMemEnd) + 1)

#define kHighShadowBeg MEM_TO_SHADOW(kHighMemBeg)
#define kHighShadowEnd MEM_TO_SHADOW(kHighMemEnd)

#define kMidShadowBeg MEM_TO_SHADOW(kMidMemBeg)
#define kMidShadowEnd MEM_TO_SHADOW(kMidMemEnd)

// With the zero shadow base we can not actually map pages starting from 0.
// This constant is somewhat arbitrary.
#define kZeroBaseShadowStart 0
#define kZeroBaseMaxShadowStart (1 << 18)

#define kShadowGapBeg (kLowShadowEnd ? kLowShadowEnd + 1 : kZeroBaseShadowStart)
#define kShadowGapEnd ((kMidMemBeg ? kMidShadowBeg : kHighShadowBeg) - 1)

#define kShadowGap2Beg (kMidMemBeg ? kMidShadowEnd + 1 : 0)
#define kShadowGap2End (kMidMemBeg ? kMidMemBeg - 1 : 0)

#define kShadowGap3Beg (kMidMemBeg ? kMidMemEnd + 1 : 0)
#define kShadowGap3End (kMidMemBeg ? kHighShadowBeg - 1 : 0)

namespace __cmsan {

static inline bool AddrIsInLowMem(uptr a) { return a <= kLowMemEnd; }

static inline bool AddrIsInLowShadow(uptr a) {
  return a >= kLowShadowBeg && a <= kLowShadowEnd;
}

static inline bool AddrIsInMidMem(uptr a) {
  return kMidMemBeg && a >= kMidMemBeg && a <= kMidMemEnd;
}

static inline bool AddrIsInMidShadow(uptr a) {
  return kMidMemBeg && a >= kMidShadowBeg && a <= kMidShadowEnd;
}

static inline bool AddrIsInHighMem(uptr a) {
  return kHighMemBeg && a >= kHighMemBeg && a <= kHighMemEnd;
}

static inline bool AddrIsInHighShadow(uptr a) {
  return kHighMemBeg && a >= kHighShadowBeg && a <= kHighShadowEnd;
}

static inline bool AddrIsInShadowGap(uptr a) {
  if (kMidMemBeg) {
    if (a <= kShadowGapEnd)
      return SHADOW_OFFSET == 0 || a >= kShadowGapBeg;
    return (a >= kShadowGap2Beg && a <= kShadowGap2End) ||
           (a >= kShadowGap3Beg && a <= kShadowGap3End);
  }
  // In zero-based shadow mode we treat addresses near zero as addresses
  // in shadow gap as well.
  if (SHADOW_OFFSET == 0)
    return a <= kShadowGapEnd;
  return a >= kShadowGapBeg && a <= kShadowGapEnd;
}

} // namespace __cmsan

namespace __cmsan {

static inline bool AddrIsInMem(uptr a) {
  return AddrIsInLowMem(a) || AddrIsInMidMem(a) || AddrIsInHighMem(a) ||
         (flags()->protect_shadow_gap == 0 && AddrIsInShadowGap(a));
}

static inline uptr MemToShadow(uptr p) {
  CHECK(AddrIsInMem(p));
  return MEM_TO_SHADOW(p);
}

static inline bool AddrIsInShadow(uptr a) {
  return AddrIsInLowShadow(a) || AddrIsInMidShadow(a) || AddrIsInHighShadow(a);
}

static inline bool AddrIsAlignedByGranularity(uptr a) {
  return (a & (SHADOW_GRANULARITY - 1)) == 0;
}

static inline bool AddressIsPoisoned(uptr a) {
  const uptr kAccessSize = 1;
  u8 *shadow_address = (u8 *)MEM_TO_SHADOW(a);
  s8 shadow_value = *shadow_address;
  if (shadow_value) {
    u8 last_accessed_byte = (a & (SHADOW_GRANULARITY - 1)) + kAccessSize - 1;
    return (last_accessed_byte >= shadow_value);
  }
  return false;
}

} // namespace __cmsan

#endif // CMSAN_MAPPING_H
