#ifndef CMSAN_CONSTRAINFUNC_DEF_H
#define CMSAN_CONSTRAINFUNC_DEF_H
 
#include <stdint.h>

typedef void (*ConstrainFunc1)(uintptr_t, void*);
typedef void (*ConstrainFunc2)(uintptr_t, void*);
typedef void (*ConstrainFunc4)(uintptr_t, void*);
typedef void (*ConstrainFunc8)(uintptr_t, void*);
typedef void (*ConstrainFunc16)(uintptr_t, void*);
typedef void (*ConstrainFuncN)(uintptr_t, uintptr_t, void*);

enum {
  CONSTRAINFUNC1TY,
  CONSTRAINFUNC2TY,
  CONSTRAINFUNC4TY,
  CONSTRAINFUNC8TY,
  CONSTRAINFUNC16TY,
  CONSTRAINFUNCNTY,
};

#endif
