#ifndef CMSAN_INTERVAL_H
#define CMSAN_INTERVAL_H

#include "cmsan_constrainfunc_def.h"

#ifdef __cplusplus
extern "C" {
#endif

struct MemRange {
  uintptr_t start, end;
  void *fn;
  uint8_t type;
};

struct MemRange *CmsanIntervalSearch(uintptr_t query);
void CmsanIntervalExecuteAll(uintptr_t start, uintptr_t end);
void CmsanIntervalUnset(uintptr_t start, uintptr_t end);
void CmsanIntervalSet(uintptr_t start, uintptr_t end, void *fn, uint8_t type);

#ifdef __cplusplus
}
#endif

#endif
