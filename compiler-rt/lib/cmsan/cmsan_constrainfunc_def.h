#ifndef CMSAN_CONSTRAINFUNC_DEF_H
#define CMSAN_CONSTRAINFUNC_DEF_H

#include <stdint.h>

typedef void (*ConstrainFunc1)(uintptr_t);
typedef void (*ConstrainFunc2)(uintptr_t);
typedef void (*ConstrainFunc4)(uintptr_t);
typedef void (*ConstrainFunc8)(uintptr_t);
typedef void (*ConstrainFunc16)(uintptr_t);
typedef void (*ConstrainFuncN)(uintptr_t, uintptr_t);

enum {
  CONSTRAINFUNC1TY,
  CONSTRAINFUNC2TY,
  CONSTRAINFUNC4TY,
  CONSTRAINFUNC8TY,
  CONSTRAINFUNC16TY,
  CONSTRAINFUNCNTY,
};

#endif
