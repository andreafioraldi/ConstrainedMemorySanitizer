#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_CONSTRAINEDMEMORYPASS_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_CONSTRAINEDMEMORYPASS_H

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

/// Public interface to the cmsan sanitizer pass for instrumenting code
class ConstrainedMemorySanitizerPass
    : public PassInfoMixin<ConstrainedMemorySanitizerPass> {
public:
  explicit ConstrainedMemorySanitizerPass();
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

/// Public interface to the cmsan sanitizer module pass for instrumenting code
///
/// This adds 'cmsan.module_ctor' to 'llvm.global_ctors'. This pass may also
/// run intependently of the function address sanitizer.
class ModuleConstrainedMemorySanitizerPass
    : public PassInfoMixin<ModuleConstrainedMemorySanitizerPass> {
public:
  explicit ModuleConstrainedMemorySanitizerPass();
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

// Insert ConstrainedMemorySanitizer instrumentation
FunctionPass *createConstrainedMemorySanitizerFunctionPass();
ModulePass *createModuleConstrainedMemorySanitizerLegacyPassPass();

} // namespace llvm

#endif
