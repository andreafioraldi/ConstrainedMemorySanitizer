# ConstrainedMemorySanitizer

This LLVM fork introduces ConstrainedMemorySanitizer, or CMSan, a sanitizer that allows the user to specify fast watchpoints to check for invariants when the watched memory is used.

This can be used to spot logic bugs for instance.

This is a prototype tested only on x86_64 and it is not thread safe.

Based on [LLVM 10.0.0-rc4](https://github.com/llvm/llvm-project/releases/tag/llvmorg-10.0.0-rc4).

## Build & Install

Build the release version of Clang using:

```
mkdir BUILD
cd BUILD
sudo mkdir /opt/cmsan_llvm10/

cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" -DCMAKE_INSTALL_PREFIX=/opt/cmsan_llvm10 -DCMAKE_BUILD_TYPE=Release ../llvm
make -j `nproc`
sudo make install
```

You will have your LLVM 10 installation in `/opt/cmsan_llvm10/`.

## Usage

You can compile using the `-fsanitize=cmsan` flag of Clang to enable CMSan. By dafault only memory reads are watched, you can change this behaviour passing `-mllvm -cmsan-instrument-reads=BOOL` for reads and `-mllvm -cmsan-instrument-writes=BOOL` for writes.

Inside the source code, you must use the `__cmsan_constrainX` to set a watchpoint in form of a callback to a specific memory area. `__cmsan_unconstrainX` removes them. You can include [`compiler-rt/include/sanitizer/cmsan_interface.h`](compiler-rt/include/sanitizer/cmsan_interface.h) to access the prototypes.

The avaiable routines to set/unset memory callbacks are:

```c
void __cmsan_constrain1(uint8_t *p, ConstrainFunc1 fn);
void __cmsan_constrain2(uint16_t *p, ConstrainFunc2 fn);
void __cmsan_constrain4(uint32_t *p, ConstrainFunc4 fn);
void __cmsan_constrain8(uint64_t *p, ConstrainFunc8 fn);
void __cmsan_constrain16(CMSAN_U128P p, ConstrainFunc16 fn);
void __cmsan_constrainN(const volatile void *p, size_t size, ConstrainFuncN fn);
void __cmsan_unconstrain1(uint8_t *p);
void __cmsan_unconstrain2(uint16_t *p);
void __cmsan_unconstrain4(uint32_t *p);
void __cmsan_unconstrain8(uint64_t *p);
void __cmsan_unconstrain16(CMSAN_U128P p);
void __cmsan_unconstrainN(const volatile void *p, size_t size);
```

The callbacks prototypes must match the following types:

```c
typedef void (*ConstrainFunc1)(uint8_t *, void*);
typedef void (*ConstrainFunc2)(uint16_t *, void*);
typedef void (*ConstrainFunc4)(uint32_t *, void*);
typedef void (*ConstrainFunc8)(uint64_t *, void*);
typedef void (*ConstrainFunc16)(CMSAN_U128P, void*);
typedef void (*ConstrainFuncN)(const volatile void *, size_t, void*);
```

Where the first argument is the pointer to the watched memory as passed to `__cmsan_constrainX`, the second is the address of the code from which the load/store hook is called.

Inside the callbacks, you can use `CMSAN_ASSERT` to check the invariants. When violated, it will print the violated check and a stracktrace.

Several macros for binary comparisons to have better error messages are avaiable too: `CMSAN_ASSERT_LT`, `CMSAN_ASSERT_LE`, `CMSAN_ASSERT_GT`, `CMSAN_ASSERT_GE`, `CMSAN_ASSERT_EQ`, `CMSAN_ASSERT_NE`.

As this sanitizer uses a shadow memory, you will have troubles to use it combined with other shadow memory based sanitizers such as ASan and MSan, but works with UBSan.
