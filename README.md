# ConstrainedMemorySanitizer

Based on [LLVM 10.0.0-rc4](https://github.com/llvm/llvm-project/releases/tag/llvmorg-10.0.0-rc4).

Compile it with:

```
mkdir BUILD
cd BUILD
sudo mkdir /opt/myllvm10/

cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;libcxx;libcxxabi;compiler-rt" -DCMAKE_INSTALL_PREFIX=/opt/myllvm10 -DCMAKE_BUILD_TYPE=Debug ../llvm

make -j `nproc`

```
