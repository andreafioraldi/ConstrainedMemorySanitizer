//===- ConstrainedMemorySanitizer.cpp -------------------------------------===//
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

#include "llvm/Transforms/Instrumentation/ConstrainedMemorySanitizer.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/InitializePasses.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>

using namespace llvm;

#define DEBUG_TYPE "cmsan"

static const uint64_t kDefaultShadowScale = 3;
static const uint64_t kDefaultShadowOffset32 = 1ULL << 29;
static const uint64_t kDefaultShadowOffset64 = 1ULL << 44;

// Accesses sizes are powers of two: 1, 2, 4, 8, 16.
static const size_t kNumberOfAccessSizes = 5;

static const char *const kCmsanModuleCtorName = "cmsan.module_ctor";
static const uint64_t kCmsanCtorAndDtorPriority = 1;

static const char *const kCmsanInitName = "__cmsan_init";

// This flag may need to be replaced with -f[no-]cmsan-reads.
static cl::opt<bool> ClInstrumentReads("cmsan-instrument-reads",
                                       cl::desc("instrument read instructions"),
                                       cl::Hidden, cl::init(true));

static cl::opt<bool> ClInstrumentAtomics(
    "cmsan-instrument-atomics",
    cl::desc("instrument atomic instructions (rmw, cmpxchg)"), cl::Hidden,
    cl::init(true));

static cl::opt<std::string>
    ClMemoryAccessCallbackPrefix("cmsan-memory-access-callback-prefix",
                                 cl::desc("Prefix for memory access callbacks"),
                                 cl::Hidden, cl::init("__cmsan_"));

static cl::opt<uint32_t>
    ClForceExperiment("cmsan-force-experiment",
                      cl::desc("Force optimization experiment (for testing)"),
                      cl::Hidden, cl::init(0));

STATISTIC(NumInstrumentedReads, "Number of instrumented reads");
STATISTIC(NumInstrumentedWrites, "Number of instrumented writes");

namespace {

struct ShadowMapping {
  int Scale;
  uint64_t Offset;
};

static ShadowMapping getShadowMapping(Triple &TargetTriple, int LongSize) {
  assert(TargetTriple.isOSLinux());

  ShadowMapping Mapping;
  Mapping.Scale = kDefaultShadowScale;

  if (LongSize == 32) {
    Mapping.Offset = kDefaultShadowOffset32;
  } else { // LongSize == 64
    Mapping.Offset = kDefaultShadowOffset64;
  }

  return Mapping;
}

static size_t TypeSizeToSizeIndex(uint32_t TypeSize) {
  size_t Res = countTrailingZeros(TypeSize / 8);
  assert(Res < kNumberOfAccessSizes);
  return Res;
}

} // namespace

struct ConstrainedMemorySanitizer {
  ConstrainedMemorySanitizer(Module &M) {
    C = &(M.getContext());
    LongSize = M.getDataLayout().getPointerSizeInBits();
    IntptrTy = Type::getIntNTy(*C, LongSize);
    TargetTriple = Triple(M.getTargetTriple());

    Mapping = getShadowMapping(TargetTriple, LongSize);
  }

  Value *isInterestingMemoryAccess(Instruction *I, bool *IsWrite,
                                   uint64_t *TypeSize, unsigned *Alignment,
                                   Value **MaybeMask = nullptr);

  void instrumentMop(ObjectSizeOffsetVisitor &ObjSizeVis, Instruction *I,
                     const DataLayout &DL);
  void instrumentAddress(Instruction *OrigIns, Instruction *Instr, Value *Addr,
                         uint32_t TypeSize, bool IsWrite, Value *SizeArgument,
                         uint32_t Exp);
  // void instrumentUnusualSizeOrAlignment(Instruction *I,
  //                                      Instruction *InsertBefore, Value
  //                                      *Addr, uint32_t TypeSize, bool
  //                                      IsWrite, Value *SizeArgument uint32_t
  //                                      Exp);
  void instrumentMemIntrinsic(MemIntrinsic *MI);
  // Value *memToShadow(Value *Shadow, IRBuilder<> &IRB);
  bool instrumentFunction(Function &F, const TargetLibraryInfo *TLI);
  // bool maybeInsertCmsanInitAtFunctionEntry(Function &F);
  // void maybeInsertDynamicShadowAtFunctionEntry(Function &F);

private:
  void initializeCallbacks(Module &M);

  LLVMContext *C;
  Triple TargetTriple;
  int LongSize;
  Type *IntptrTy;
  ShadowMapping Mapping;

  // These arrays is indexed by AccessIsWrite, Experiment and log2(AccessSize).
  FunctionCallee CmsanMemoryAccessCallback[2][2][kNumberOfAccessSizes];

  // These arrays is indexed by AccessIsWrite and Experiment.
  FunctionCallee CmsanMemoryAccessCallbackSized[2][2];

  FunctionCallee CmsanMemmove, CmsanMemcpy, CmsanMemset;
  InlineAsm *EmptyAsm;
};

class ModuleConstrainedMemorySanitizer {
public:
  ModuleConstrainedMemorySanitizer(Module &M) {
    C = &(M.getContext());
    LongSize = M.getDataLayout().getPointerSizeInBits();
    IntptrTy = Type::getIntNTy(*C, LongSize);
    TargetTriple = Triple(M.getTargetTriple());

    Mapping = getShadowMapping(TargetTriple, LongSize);
  }

  bool instrumentModule(Module &);

private:
  void initializeCallbacks(Module &M);

  LLVMContext *C;
  Triple TargetTriple;
  int LongSize;
  Type *IntptrTy;
  ShadowMapping Mapping;

  // These arrays is indexed by AccessIsWrite, Experiment and log2(AccessSize).
  FunctionCallee CmsanMemoryAccessCallback[2][2][kNumberOfAccessSizes];

  // These arrays is indexed by AccessIsWrite and Experiment.
  FunctionCallee CmsanMemoryAccessCallbackSized[2][2];

  FunctionCallee CmsanMemmove, CmsanMemcpy, CmsanMemset;
  InlineAsm *EmptyAsm;

  Function *CmsanCtorFunction = nullptr;
};

//// Passes

ModuleConstrainedMemorySanitizerPass::ModuleConstrainedMemorySanitizerPass() {}

PreservedAnalyses
ModuleConstrainedMemorySanitizerPass::run(Module &M,
                                          ModuleAnalysisManager &AM) {

  ModuleConstrainedMemorySanitizer Sanitizer(M);
  if (Sanitizer.instrumentModule(M))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

ConstrainedMemorySanitizerPass::ConstrainedMemorySanitizerPass() {}

PreservedAnalyses
ConstrainedMemorySanitizerPass::run(Function &F, FunctionAnalysisManager &AM) {
  // auto &MAMProxy = AM.getResult<ModuleAnalysisManagerFunctionProxy>(F);
  // auto &MAM = MAMProxy.getManager();
  Module &M = *F.getParent();
  const TargetLibraryInfo *TLI = &AM.getResult<TargetLibraryAnalysis>(F);
  ConstrainedMemorySanitizer Sanitizer(M);
  if (Sanitizer.instrumentFunction(F, TLI))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

//// Methods

void ModuleConstrainedMemorySanitizer::initializeCallbacks(Module &M) {
  IRBuilder<> IRB(*C);
  // Create __cmsan_access* callbacks.
  // IsWrite, TypeSize and Exp are encoded in the function name.
  for (int Exp = 0; Exp < 2; Exp++) {
    for (size_t AccessIsWrite = 0; AccessIsWrite <= 1; AccessIsWrite++) {
      const std::string TypeStr = AccessIsWrite ? "store" : "load";
      const std::string ExpStr = Exp ? "exp_" : "";

      SmallVector<Type *, 3> Args2 = {IntptrTy, IntptrTy};
      SmallVector<Type *, 2> Args1{1, IntptrTy};
      if (Exp) {
        Type *ExpType = Type::getInt32Ty(*C);
        Args2.push_back(ExpType);
        Args1.push_back(ExpType);
      }
      CmsanMemoryAccessCallbackSized[AccessIsWrite][Exp] =
          M.getOrInsertFunction(
              ClMemoryAccessCallbackPrefix + ExpStr + TypeStr + "N",
              FunctionType::get(IRB.getVoidTy(), Args2, false));

      for (size_t AccessSizeIndex = 0; AccessSizeIndex < kNumberOfAccessSizes;
           AccessSizeIndex++) {
        const std::string Suffix = TypeStr + itostr(1ULL << AccessSizeIndex);
        CmsanMemoryAccessCallback[AccessIsWrite][Exp][AccessSizeIndex] =
            M.getOrInsertFunction(
                ClMemoryAccessCallbackPrefix + ExpStr + Suffix,
                FunctionType::get(IRB.getVoidTy(), Args1, false));
      }
    }
  }

  const std::string MemIntrinCallbackPrefix = ClMemoryAccessCallbackPrefix;
  CmsanMemmove = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memmove",
                                       IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
                                       IRB.getInt8PtrTy(), IntptrTy);
  CmsanMemcpy = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memcpy",
                                      IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
                                      IRB.getInt8PtrTy(), IntptrTy);
  CmsanMemset = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memset",
                                      IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
                                      IRB.getInt32Ty(), IntptrTy);

  // We insert an empty inline asm after __cmsan_access* to avoid callback
  // merge.
  EmptyAsm = InlineAsm::get(FunctionType::get(IRB.getVoidTy(), false),
                            StringRef(""), StringRef(""),
                            /*hasSideEffects=*/true);
}

bool ModuleConstrainedMemorySanitizer::instrumentModule(Module &M) {
  initializeCallbacks(M);

  std::tie(CmsanCtorFunction, std::ignore) =
      createSanitizerCtorAndInitFunctions(M, kCmsanModuleCtorName,
                                          kCmsanInitName, /*InitArgTypes=*/{},
                                          /*InitArgs=*/{}, "");

  appendToGlobalCtors(M, CmsanCtorFunction, kCmsanCtorAndDtorPriority);

  return true;
}

void ConstrainedMemorySanitizer::initializeCallbacks(Module &M) {
  IRBuilder<> IRB(*C);
  // Create __cmsan_access* callbacks.
  // IsWrite, TypeSize and Exp are encoded in the function name.
  for (int Exp = 0; Exp < 2; Exp++) {
    for (size_t AccessIsWrite = 0; AccessIsWrite <= 1; AccessIsWrite++) {
      const std::string TypeStr = AccessIsWrite ? "store" : "load";
      const std::string ExpStr = Exp ? "exp_" : "";

      SmallVector<Type *, 3> Args2 = {IntptrTy, IntptrTy};
      SmallVector<Type *, 2> Args1{1, IntptrTy};
      if (Exp) {
        Type *ExpType = Type::getInt32Ty(*C);
        Args2.push_back(ExpType);
        Args1.push_back(ExpType);
      }
      CmsanMemoryAccessCallbackSized[AccessIsWrite][Exp] =
          M.getOrInsertFunction(
              ClMemoryAccessCallbackPrefix + ExpStr + TypeStr + "N",
              FunctionType::get(IRB.getVoidTy(), Args2, false));

      for (size_t AccessSizeIndex = 0; AccessSizeIndex < kNumberOfAccessSizes;
           AccessSizeIndex++) {
        const std::string Suffix = TypeStr + itostr(1ULL << AccessSizeIndex);
        CmsanMemoryAccessCallback[AccessIsWrite][Exp][AccessSizeIndex] =
            M.getOrInsertFunction(
                ClMemoryAccessCallbackPrefix + ExpStr + Suffix,
                FunctionType::get(IRB.getVoidTy(), Args1, false));
      }
    }
  }

  const std::string MemIntrinCallbackPrefix = ClMemoryAccessCallbackPrefix;
  CmsanMemmove = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memmove",
                                       IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
                                       IRB.getInt8PtrTy(), IntptrTy);
  CmsanMemcpy = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memcpy",
                                      IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
                                      IRB.getInt8PtrTy(), IntptrTy);
  CmsanMemset = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memset",
                                      IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
                                      IRB.getInt32Ty(), IntptrTy);

  // We insert an empty inline asm after __cmsan_access* to avoid callback
  // merge.
  EmptyAsm = InlineAsm::get(FunctionType::get(IRB.getVoidTy(), false),
                            StringRef(""), StringRef(""),
                            /*hasSideEffects=*/true);
}

Value *ConstrainedMemorySanitizer::isInterestingMemoryAccess(
    Instruction *I, bool *IsWrite, uint64_t *TypeSize, unsigned *Alignment,
    Value **MaybeMask) {
  // Skip memory accesses inserted by another instrumentation.
  if (I->hasMetadata("nosanitize"))
    return nullptr;

  Value *PtrOperand = nullptr;
  const DataLayout &DL = I->getModule()->getDataLayout();
  if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
    if (!ClInstrumentReads)
      return nullptr;
    *IsWrite = false;
    *TypeSize = DL.getTypeStoreSizeInBits(LI->getType());
    *Alignment = LI->getAlignment();
    PtrOperand = LI->getPointerOperand();
  } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
    *IsWrite = true;
    *TypeSize = DL.getTypeStoreSizeInBits(SI->getValueOperand()->getType());
    *Alignment = SI->getAlignment();
    PtrOperand = SI->getPointerOperand();
  } else if (AtomicRMWInst *RMW = dyn_cast<AtomicRMWInst>(I)) {
    if (!ClInstrumentAtomics)
      return nullptr;
    *IsWrite = true;
    *TypeSize = DL.getTypeStoreSizeInBits(RMW->getValOperand()->getType());
    *Alignment = 0;
    PtrOperand = RMW->getPointerOperand();
  } else if (AtomicCmpXchgInst *XCHG = dyn_cast<AtomicCmpXchgInst>(I)) {
    if (!ClInstrumentAtomics)
      return nullptr;
    *IsWrite = true;
    *TypeSize = DL.getTypeStoreSizeInBits(XCHG->getCompareOperand()->getType());
    *Alignment = 0;
    PtrOperand = XCHG->getPointerOperand();
  } else if (auto CI = dyn_cast<CallInst>(I)) {
    auto *F = dyn_cast<Function>(CI->getCalledValue());
    if (F && (F->getName().startswith("llvm.masked.load.") ||
              F->getName().startswith("llvm.masked.store."))) {
      unsigned OpOffset = 0;
      if (F->getName().startswith("llvm.masked.store.")) {
        // Masked store has an initial operand for the value.
        OpOffset = 1;
        *IsWrite = true;
      } else {
        if (!ClInstrumentReads)
          return nullptr;
        *IsWrite = false;
      }

      auto BasePtr = CI->getOperand(0 + OpOffset);
      auto Ty = cast<PointerType>(BasePtr->getType())->getElementType();
      *TypeSize = DL.getTypeStoreSizeInBits(Ty);
      if (auto AlignmentConstant =
              dyn_cast<ConstantInt>(CI->getOperand(1 + OpOffset)))
        *Alignment = (unsigned)AlignmentConstant->getZExtValue();
      else
        *Alignment = 1; // No alignment guarantees. We probably got Undef
      if (MaybeMask)
        *MaybeMask = CI->getOperand(2 + OpOffset);
      PtrOperand = BasePtr;
    }
  }

  if (PtrOperand) {
    // Do not instrument acesses from different address spaces; we cannot deal
    // with them.
    Type *PtrTy = cast<PointerType>(PtrOperand->getType()->getScalarType());
    if (PtrTy->getPointerAddressSpace() != 0)
      return nullptr;

    // Ignore swifterror addresses.
    // swifterror memory addresses are mem2reg promoted by instruction
    // selection. As such they cannot have regular uses like an instrumentation
    // function and it makes no sense to track them as memory.
    if (PtrOperand->isSwiftError())
      return nullptr;
  }

  return PtrOperand;
}

bool ConstrainedMemorySanitizer::instrumentFunction(
    Function &F, const TargetLibraryInfo *TLI) {
  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage)
    return false;
  if (F.getName().startswith("__cmsan_"))
    return false;
  if (F.getName().startswith("__ubsan_"))
    return false;

  bool FunctionModified = false;

  // Leave if the function doesn't need instrumentation.
  // if (!F.hasFnAttribute(Attribute::SanitizeConstrainedMemory))
  //  return FunctionModified;

  LLVM_DEBUG(dbgs() << "CMSAN instrumenting:\n" << F << "\n");

  initializeCallbacks(*F.getParent());

  // We want to instrument every address only once per basic block (unless there
  // are calls between uses).
  SmallVector<Instruction *, 16> ToInstrument;
  SmallVector<BasicBlock *, 16> AllBlocks;
  bool IsWrite;
  unsigned Alignment;
  uint64_t TypeSize;

  // Fill the set of memory operations to instrument.
  for (auto &BB : F) {
    AllBlocks.push_back(&BB);
    int NumInsnsPerBB = 0;
    for (auto &Inst : BB) {
      Value *MaybeMask = nullptr;
      Value *Addr;
      if ((Addr = isInterestingMemoryAccess(&Inst, &IsWrite, &TypeSize,
                                            &Alignment, &MaybeMask)) ||
          isa<MemIntrinsic>(Inst)) {
        // ok, take it.
      } else {
        if (CallInst *CI = dyn_cast<CallInst>(&Inst))
          maybeMarkSanitizerLibraryCallNoBuiltin(CI, TLI);
        continue;
      }
      ToInstrument.push_back(&Inst);
      NumInsnsPerBB++;
    }
  }

  const DataLayout &DL = F.getParent()->getDataLayout();
  ObjectSizeOpts ObjSizeOpts;
  ObjSizeOpts.RoundToAlign = true;
  ObjectSizeOffsetVisitor ObjSizeVis(DL, TLI, F.getContext(), ObjSizeOpts);

  // Instrument.
  int NumInstrumented = 0;
  for (auto Inst : ToInstrument) {
    // if (ClDebugMin < 0 || ClDebugMax < 0 ||
    //    (NumInstrumented >= ClDebugMin && NumInstrumented <= ClDebugMax)) {
    if (isInterestingMemoryAccess(Inst, &IsWrite, &TypeSize, &Alignment))
      instrumentMop(ObjSizeVis, Inst, F.getParent()->getDataLayout());
    else
      instrumentMemIntrinsic(cast<MemIntrinsic>(Inst));
    //}
    NumInstrumented++;
  }

  if (NumInstrumented > 0)
    FunctionModified = true;

  LLVM_DEBUG(dbgs() << "CMSAN done instrumenting: " << FunctionModified << " "
                    << F << "\n");

  return FunctionModified;
}

void ConstrainedMemorySanitizer::instrumentMop(
    ObjectSizeOffsetVisitor &ObjSizeVis, Instruction *I, const DataLayout &DL) {
  bool IsWrite = false;
  unsigned Alignment = 0;
  uint64_t TypeSize = 0;
  Value *MaybeMask = nullptr;
  Value *Addr =
      isInterestingMemoryAccess(I, &IsWrite, &TypeSize, &Alignment, &MaybeMask);
  assert(Addr);

  uint32_t Exp = ClForceExperiment;

  if (IsWrite)
    NumInstrumentedWrites++;
  else
    NumInstrumentedReads++;

  // unsigned Granularity = 1 << Mapping.Scale;
  // if (MaybeMask) {
  //   instrumentMaskedLoadOrStore(this, DL, IntptrTy, MaybeMask, I, Addr,
  //                               Alignment, Granularity, TypeSize, IsWrite,
  //                               nullptr, Exp);
  // } else {
  //  doInstrumentAddress(this, I, I, Addr, Alignment, Granularity, TypeSize,
  //                      IsWrite, nullptr, Exp);
  // }

  // TODO(andrea) do we need a special case for unaligned accesses?
  // TODO(andrea) for sure we need it for unusual sizes
  if (TypeSize == 8 || TypeSize == 16 || TypeSize == 32 || TypeSize == 64 ||
       TypeSize == 128)
    instrumentAddress(I, I, Addr, TypeSize, IsWrite, nullptr, Exp);
}

void ConstrainedMemorySanitizer::instrumentAddress(
    Instruction *OrigIns, Instruction *Instr, Value *Addr, uint32_t TypeSize,
    bool IsWrite, Value *SizeArgument, uint32_t Exp) {
  IRBuilder<> IRB(Instr->getNextNode());
  Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
  size_t AccessSizeIndex = TypeSizeToSizeIndex(TypeSize);

  if (Exp == 0)
    IRB.CreateCall(CmsanMemoryAccessCallback[IsWrite][0][AccessSizeIndex],
                   AddrLong);
  else
    IRB.CreateCall(CmsanMemoryAccessCallback[IsWrite][1][AccessSizeIndex],
                   {AddrLong, ConstantInt::get(IRB.getInt32Ty(), Exp)});

  // TODO(andrea) inline instrumentation
}

// Instrument memset/memmove/memcpy
void ConstrainedMemorySanitizer::instrumentMemIntrinsic(MemIntrinsic *MI) {
  IRBuilder<> IRB(MI->getNextNode());
  if (isa<MemTransferInst>(MI)) {
    IRB.CreateCall(
        isa<MemMoveInst>(MI) ? CmsanMemmove : CmsanMemcpy,
        {IRB.CreatePointerCast(MI->getOperand(0), IRB.getInt8PtrTy()),
         IRB.CreatePointerCast(MI->getOperand(1), IRB.getInt8PtrTy()),
         IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
  } else if (isa<MemSetInst>(MI)) {
    IRB.CreateCall(
        CmsanMemset,
        {IRB.CreatePointerCast(MI->getOperand(0), IRB.getInt8PtrTy()),
         IRB.CreateIntCast(MI->getOperand(1), IRB.getInt32Ty(), false),
         IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
  }
  MI->eraseFromParent();
}

//// Legacy passes

class ConstrainedMemorySanitizerLegacyPass : public FunctionPass {
public:
  static char ID;

  explicit ConstrainedMemorySanitizerLegacyPass() : FunctionPass(ID) {
    initializeConstrainedMemorySanitizerLegacyPassPass(
        *PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override {
    return "ConstrainedMemorySanitizerLegacyPass";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<TargetLibraryInfoWrapperPass>();
  }

  bool runOnFunction(Function &F) override {
    Module &M = *F.getParent();
    const TargetLibraryInfo *TLI =
        &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
    ConstrainedMemorySanitizer Sanitizer(M);
    return Sanitizer.instrumentFunction(F, TLI);
  }
};

class ModuleConstrainedMemorySanitizerLegacyPass : public ModulePass {
public:
  static char ID;

  explicit ModuleConstrainedMemorySanitizerLegacyPass() : ModulePass(ID) {
    initializeModuleConstrainedMemorySanitizerLegacyPassPass(
        *PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override {
    return "ModuleConstrainedMemorySanitizerLegacyPass";
  }

  bool runOnModule(Module &M) override {
    ModuleConstrainedMemorySanitizer Sanitizer(M);
    return Sanitizer.instrumentModule(M);
  }
};

char ConstrainedMemorySanitizerLegacyPass::ID = 0;
char ModuleConstrainedMemorySanitizerLegacyPass::ID = 0;

INITIALIZE_PASS(ConstrainedMemorySanitizerLegacyPass, "cmsan",
                "ConstrainedMemorySanitizer.", false, false)

INITIALIZE_PASS(ModuleConstrainedMemorySanitizerLegacyPass, "cmsan-module",
                "ConstrainedMemorySanitizer. ModulePass", false, false)

FunctionPass *llvm::createConstrainedMemorySanitizerFunctionPass() {
  return new ConstrainedMemorySanitizerLegacyPass();
}

ModulePass *llvm::createModuleConstrainedMemorySanitizerLegacyPassPass() {
  return new ModuleConstrainedMemorySanitizerLegacyPass();
}

/* // For debugging
static RegisterPass<ConstrainedMemorySanitizerLegacyPass>
    X("cmsan", "ConstrainedMemorySanitizerLegacyPass",
      true, // This pass doesn't modify the CFG => true
      false // This pass is not a pure analysis pass => false
    );

static RegisterPass<ModuleConstrainedMemorySanitizerLegacyPass>
    Y("cmsan-module", "ModuleConstrainedMemorySanitizerLegacyPass",
      true, // This pass doesn't modify the CFG => true
      false // This pass is not a pure analysis pass => false
    );
*/
